"""探测引擎：在 [min_size, max_size] 内二分搜索可确认的最大 UDP 负载。

判定规则（与需求一一对应）：
- 每次探测运行使用独立 socket（临时端口）与独立探测编号（UUID），
  并发探测、迟到回包不会串入其他结论；
- 探测 socket 设置 DF 位，禁止 IP 分片；发送失败（如 EMSGSIZE）与超时
  同等对待；
- 超时与 RTT 以**逐包内核收包时刻**（SO_TIMESTAMPNS）为准：
  回包在时限内到达内核即算成功，哪怕事件循环稍后才读到它；
  内核收包时刻超过时限的回包不予采信，既不能推进二分，也不会
  留作下一次探测的回包；
- 收到匹配回包却无法确认其内核收包时刻时，无法判定是否超时，
  本次探测终止并报告 undetermined，已确认的下界保留；
- 大包超时或发送失败时，先用小包（small_size）复核链路：
  小包通 → 链路正常，确为尺寸受限，继续二分；
  小包也不通 → 链路不确定，立即终止，绝不把该失败记为尺寸上限；
- 探测期间回显端配置（epoch）变化 → 本次结论作废（invalidated）；
- 范围内全部确认 → 达到范围上限（reached_range_max）；
- 范围下限都确认不了（但链路正常）→ below_range。
"""
from __future__ import annotations

import asyncio
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import netutil
from .echo_server import EchoState
from .packets import HEADER_SIZE, MAX_UDP_PAYLOAD, build_packet, parse_packet

_RECV_BUFSIZE = 65536  # 大于最大 UDP 负载 65507，保证整包读出
_ANC_BUFSIZE = 512  # 足够容纳 SO_TIMESTAMPNS 控制消息

# ---------------------------------------------------------------------------
# API 模型
# ---------------------------------------------------------------------------


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_size: int = Field(576, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="探测范围下限（字节）")
    max_size: int = Field(1400, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="探测范围上限（字节）")
    timeout_ms: int = Field(500, ge=20, le=30000, description="单次探测等待回包超时（毫秒）")
    small_size: int = Field(64, ge=HEADER_SIZE, le=MAX_UDP_PAYLOAD, description="链路复核小包长度（字节）")
    target_host: Optional[str] = Field(None, description="回显端地址，缺省为本地回显端")
    target_port: Optional[int] = Field(None, ge=1, le=65535, description="回显端端口，缺省为本地回显端")

    @model_validator(mode="after")
    def _check_range(self) -> "ProbeRequest":
        if self.min_size > self.max_size:
            raise ValueError("min_size 不能大于 max_size")
        return self


class AttemptOut(BaseModel):
    seq: int
    size: int
    purpose: Literal["probe", "link-verify"]
    outcome: Literal["ok", "timeout", "send_error", "undetermined"]
    rtt_ms: Optional[float] = Field(
        None, description="往返时延：匹配回包的内核收包时刻 − 发送时刻（毫秒）"
    )
    kernel_recv_at: Optional[float] = Field(
        None, description="匹配回包的内核收包时刻（Unix 秒）；未收到匹配回包时为 null"
    )
    detail: Optional[str] = None


class ProbeResult(BaseModel):
    probe_id: str
    status: Literal["ok", "below_range", "undetermined", "invalidated"]
    max_confirmed_size: Optional[int] = Field(
        None, description="本次确认可用的最大 UDP 负载；undetermined 时为已确认下界，invalidated 时作废为 null"
    )
    reason: Optional[str] = Field(None, description="无法判定 / 结论作废 / 低于范围时的原因")
    reached_range_max: bool = False
    min_size: int
    max_size: int
    attempts: list[AttemptOut]
    stray_replies: int = Field(0, description="被丢弃的不对应回包数（编号/序号/长度不符）")
    late_replies: int = Field(0, description="内核收包时刻已超过时限的匹配回包数（不予采信）")
    config_epoch_start: int
    config_epoch_end: int
    df_enabled: bool = Field(..., description="探测 socket 是否成功设置 DF（禁止 IP 分片）")
    kernel_ts_enabled: bool = Field(
        ..., description="探测 socket 是否成功启用逐包内核收包时刻（SO_TIMESTAMPNS）"
    )
    target: str
    started_at: datetime
    finished_at: datetime
    duration_ms: float


# ---------------------------------------------------------------------------
# 探测引擎
# ---------------------------------------------------------------------------


class _RecvTimeUndetermined(Exception):
    """收到匹配回包，但无法确认其内核收包时刻（无法判定是否超时）。

    携带本次探测记录，由 probe() 捕获后终止二分并报告 undetermined。
    """

    def __init__(self, attempt: AttemptOut) -> None:
        super().__init__(attempt.detail or "")
        self.attempt = attempt


class Prober:
    def __init__(self, state: EchoState, default_target: tuple[str, int]) -> None:
        self._state = state
        self._default_target = default_target

    async def probe(self, req: ProbeRequest) -> ProbeResult:
        probe_id = uuid.uuid4()
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        host, port = self._default_target
        if req.target_host is not None:
            host = req.target_host
        if req.target_port is not None:
            port = req.target_port
        target = f"{host}:{port}"

        epoch_start = self._state.epoch
        attempts: list[AttemptOut] = []
        stray = 0
        late = 0
        seq = 0

        loop = asyncio.get_running_loop()
        # 异步解析目标地址，不阻塞事件循环（等待期间其他探测照常进行）；
        # 解析失败抛 OSError，由上层转为 400。
        infos = await loop.getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
        )
        sockaddr = infos[0][4]

        # 每次探测运行独立 socket（独立临时端口），并 connect 到回显端：
        # 其他运行的回包、无关数据报在内核层就被过滤，不会到达本 socket。
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue()

        def on_readable() -> None:
            """把内核已收到的数据报全部读进队列，每个包附带内核收包时刻。"""
            while True:
                try:
                    data, ancdata, _flags, _addr = sock.recvmsg(_RECV_BUFSIZE, _ANC_BUFSIZE)
                except (BlockingIOError, InterruptedError):
                    return
                except OSError as exc:
                    # 连通型 UDP 的异步 ICMP 错误（如对端端口不可达）
                    queue.put_nowait(("error", exc))
                    return
                queue.put_nowait(("data", (data, netutil.extract_kernel_timestamp(ancdata))))

        sock_fd = sock.fileno()
        try:
            sock.connect(sockaddr)
            df_ok = netutil.set_dont_fragment(sock)
            ts_ok = netutil.enable_kernel_timestamps(sock)
            loop.add_reader(sock_fd, on_readable)
        except Exception:
            sock.close()
            raise

        timeout_s = req.timeout_ms / 1000.0

        async def attempt(size: int, purpose: Literal["probe", "link-verify"]) -> AttemptOut:
            nonlocal seq, stray, late
            seq += 1
            my_seq = seq
            payload = build_packet(probe_id, my_seq, size)
            try:
                await loop.sock_sendall(sock, payload)
            except OSError as exc:
                # 发送失败（如 EMSGSIZE：DF 下超过路径 MTU）
                return AttemptOut(
                    seq=my_seq, size=size, purpose=purpose,
                    outcome="send_error",
                    detail=f"{type(exc).__name__}: {exc}",
                )
            # 内核收包时刻为 CLOCK_REALTIME，与 time.time() 同时基；
            # 等待循环另用单调时钟，二者各司其职。
            t_send_wall = time.time()
            t_send_mono = time.monotonic()
            deadline_wall = t_send_wall + timeout_s
            deadline_mono = t_send_mono + timeout_s

            def judge(data: bytes, recv_at: Optional[float]) -> Optional[AttemptOut]:
                """判定一个收到的数据报；不对应返回 None（继续等）。"""
                nonlocal stray, late
                pkt = parse_packet(data)
                if (
                    pkt is None
                    or pkt.session_id != probe_id
                    or pkt.seq != my_seq
                    or pkt.size != size
                ):
                    # 不对应回包：丢弃不采信
                    stray += 1
                    return None
                if recv_at is None:
                    # 收包时刻无法确认 → 无法判定是否超时，整个探测终止
                    raise _RecvTimeUndetermined(
                        AttemptOut(
                            seq=my_seq, size=size, purpose=purpose,
                            outcome="undetermined",
                            detail="收到匹配回包，但无法确认其内核收包时刻",
                        )
                    )
                if recv_at <= deadline_wall:
                    return AttemptOut(
                        seq=my_seq, size=size, purpose=purpose,
                        outcome="ok",
                        rtt_ms=round((recv_at - t_send_wall) * 1000.0, 3),
                        kernel_recv_at=recv_at,
                    )
                # 内核收包时刻已超过时限：迟到的回包不采信、不留存
                late += 1
                return AttemptOut(
                    seq=my_seq, size=size, purpose=purpose,
                    outcome="timeout",
                    kernel_recv_at=recv_at,
                    detail=f"匹配回包迟到：内核收包时刻已超过 {req.timeout_ms}ms 时限，不予采信",
                )

            def send_error_outcome(exc: Exception) -> AttemptOut:
                return AttemptOut(
                    seq=my_seq, size=size, purpose=purpose,
                    outcome="send_error",
                    detail=f"{type(exc).__name__}: {exc}",
                )

            # 阶段一：在单调时钟时限内等待接收队列
            while True:
                remaining = deadline_mono - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    kind, obj = await asyncio.wait_for(queue.get(), remaining)
                except asyncio.TimeoutError:
                    break
                if kind == "error":
                    return send_error_outcome(obj)  # type: ignore[arg-type]
                out = judge(*obj)  # type: ignore[misc]
                if out is not None:
                    return out
            # 阶段二：事件循环可能刚恢复——把内核缓冲读空再判一次，
            # 时限内到达（以内核收包时刻为准）的匹配回包仍然采信
            on_readable()
            while True:
                try:
                    kind, obj = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return AttemptOut(seq=my_seq, size=size, purpose=purpose, outcome="timeout")
                if kind == "error":
                    return send_error_outcome(obj)  # type: ignore[arg-type]
                out = judge(*obj)  # type: ignore[misc]
                if out is not None:
                    return out

        def epoch_broken() -> bool:
            return self._state.epoch != epoch_start

        def invalidated_result() -> tuple[str, str]:
            return (
                "invalidated",
                f"探测期间回显端配置发生变化（epoch {epoch_start} → {self._state.epoch}），本次结论作废",
            )

        status: Literal["ok", "below_range", "undetermined", "invalidated"] = "ok"
        reason: Optional[str] = None
        best: Optional[int] = None
        lo, hi = req.min_size, req.max_size

        try:
            try:
                while lo <= hi:
                    if epoch_broken():
                        status, reason = invalidated_result()
                        best = None
                        break
                    mid = (lo + hi) // 2
                    att = await attempt(mid, "probe")
                    attempts.append(att)
                    if att.outcome == "ok":
                        best = mid
                        lo = mid + 1
                        continue
                    # 大包失败（超时或发送失败）→ 小包复核链路
                    verify = await attempt(req.small_size, "link-verify")
                    attempts.append(verify)
                    if verify.outcome == "ok":
                        hi = mid - 1  # 链路正常，确为尺寸受限
                        continue
                    if epoch_broken():
                        status, reason = invalidated_result()
                        best = None
                    else:
                        status = "undetermined"
                        reason = (
                            f"{mid} 字节探测{('超时' if att.outcome == 'timeout' else '发送失败')}后，"
                            f"{req.small_size} 字节小包复核亦失败（{verify.outcome}），"
                            "链路状态不确定，不能将该失败记为尺寸上限"
                        )
                        # 保留此前已确认的下界，但绝不把失败尺寸当作上限
                    break
            except _RecvTimeUndetermined as exc:
                attempts.append(exc.attempt)
                status = "undetermined"
                reason = (
                    "收到匹配回包，但其内核收包时刻无法确认，无法判定是否超过时限；"
                    "本次探测终止，此前已确认的下界仍然有效"
                )

            if status == "ok":
                if epoch_broken():
                    status, reason = invalidated_result()
                    best = None
                elif best is None:
                    status = "below_range"
                    reason = (
                        f"链路正常（{req.small_size} 字节小包复核通过），但范围下限 "
                        f"{req.min_size} 字节未获确认，可确认上限低于探测范围"
                    )
        finally:
            loop.remove_reader(sock_fd)
            sock.close()

        finished_at = datetime.now(timezone.utc)
        return ProbeResult(
            probe_id=str(probe_id),
            status=status,
            max_confirmed_size=best,
            reason=reason,
            reached_range_max=(status == "ok" and best == req.max_size),
            min_size=req.min_size,
            max_size=req.max_size,
            attempts=attempts,
            stray_replies=stray,
            late_replies=late,
            config_epoch_start=epoch_start,
            config_epoch_end=self._state.epoch,
            df_enabled=df_ok,
            kernel_ts_enabled=ts_ok,
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
        )
