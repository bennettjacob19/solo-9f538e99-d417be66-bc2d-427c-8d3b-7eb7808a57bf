"""端到端测试：真实 UDP 回显端 + TestClient。"""
from __future__ import annotations

import asyncio
import socket
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.packets import HEADER_SIZE, build_packet, parse_packet


@pytest.fixture()
def client():
    # 每个用例一套全新 lifespan：回显端状态、epoch、历史记录都重置
    with TestClient(app) as c:
        yield c


def set_config(client, **kw):
    r = client.put("/echo/config", json=kw)
    assert r.status_code == 200, r.text
    return r.json()["epoch"]


def run_probe(client, **kw):
    kw.setdefault("timeout_ms", 150)
    r = client.post("/probe", json=kw)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- 报文编解码


class TestPackets:
    def test_roundtrip(self):
        sid = uuid.uuid4()
        data = build_packet(sid, 7, 576)
        assert len(data) == 576
        pkt = parse_packet(data)
        assert pkt is not None
        assert pkt.session_id == sid and pkt.seq == 7 and pkt.size == 576

    def test_min_and_max_size(self):
        sid = uuid.uuid4()
        assert len(build_packet(sid, 1, HEADER_SIZE)) == HEADER_SIZE
        assert len(build_packet(sid, 1, 65507)) == 65507
        with pytest.raises(ValueError):
            build_packet(sid, 1, HEADER_SIZE - 1)
        with pytest.raises(ValueError):
            build_packet(sid, 1, 65508)

    def test_reject_garbage(self):
        assert parse_packet(b"") is None
        assert parse_packet(b"x" * HEADER_SIZE) is None  # magic 不符
        data = bytearray(build_packet(uuid.uuid4(), 1, 100))
        data[-1] = 1
        assert parse_packet(bytes(data[:-1])) is None  # 长度不自洽


# ---------------------------------------------------------------- 配置接口


class TestConfig:
    def test_default_config(self, client):
        r = client.get("/echo/config")
        assert r.status_code == 200
        body = r.json()
        assert body["epoch"] == 0
        assert body["config"] == {"mode": "normal", "drop_threshold": None}

    def test_update_and_epoch_increments(self, client):
        e1 = set_config(client, mode="normal", drop_threshold=1000)
        e2 = set_config(client, mode="disconnect", drop_threshold=None)
        assert e2 == e1 + 1 == 2
        assert client.get("/echo/config").json()["config"]["mode"] == "disconnect"

    def test_invalid_config_keeps_original_state(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        before = client.get("/echo/config").json()

        for bad in (
            {"mode": "bogus"},
            {"drop_threshold": -1},
            {"drop_threshold": 70000},
            {"mode": "normal", "drop_threshold": 1000, "extra": 1},
            {"drop_threshold": "abc"},
        ):
            r = client.put("/echo/config", json=bad)
            assert r.status_code == 422, bad

        after = client.get("/echo/config").json()
        assert after["epoch"] == before["epoch"]
        assert after["config"] == before["config"]


# ---------------------------------------------------------------- 探测


class TestProbe:
    def test_no_drop_reaches_range_max(self, client):
        res = run_probe(client)
        assert res["status"] == "ok"
        assert res["max_confirmed_size"] == 1400
        assert res["reached_range_max"] is True
        assert res["df_enabled"] is True
        assert res["reason"] is None
        assert all(a["outcome"] == "ok" for a in res["attempts"])
        assert res["config_epoch_start"] == res["config_epoch_end"]

    def test_threshold_1000(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        res = run_probe(client)
        assert res["status"] == "ok"
        assert res["max_confirmed_size"] == 1000
        assert res["reached_range_max"] is False
        # 失败的大包后面必须紧跟一次小包复核，且复核通过
        attempts = res["attempts"]
        for i, a in enumerate(attempts):
            if a["purpose"] == "probe" and a["outcome"] != "ok":
                assert a["size"] > 1000
                nxt = attempts[i + 1]
                assert nxt["purpose"] == "link-verify" and nxt["outcome"] == "ok"
        # 所有确认成功的大包都不超过阈值
        assert all(
            a["size"] <= 1000
            for a in attempts
            if a["purpose"] == "probe" and a["outcome"] == "ok"
        )

    def test_disconnect_reports_undetermined(self, client):
        set_config(client, mode="disconnect")
        res = run_probe(client, timeout_ms=100)
        assert res["status"] == "undetermined"
        assert res["max_confirmed_size"] is None
        assert "链路状态不确定" in res["reason"]
        purposes = [a["purpose"] for a in res["attempts"]]
        assert "link-verify" in purposes
        assert all(a["outcome"] != "ok" for a in res["attempts"])

    def test_below_range(self, client):
        # 阈值 100：小包(64B)能通，范围下限 576 通不了
        set_config(client, mode="normal", drop_threshold=100)
        res = run_probe(client, timeout_ms=100)
        assert res["status"] == "below_range"
        assert res["max_confirmed_size"] is None
        assert "低于探测范围" in res["reason"]

    def test_config_change_during_probe_invalidates(self, client):
        set_config(client, mode="normal", drop_threshold=700)

        def change_config():
            time.sleep(0.15)
            client.put("/echo/config", json={"mode": "normal", "drop_threshold": 1400})

        t = threading.Thread(target=change_config)
        t.start()
        # 首次二分 mid=988 > 700 会超时（600ms），期间配置被修改
        res = run_probe(client, timeout_ms=600)
        t.join()
        assert res["status"] == "invalidated"
        assert res["max_confirmed_size"] is None
        assert "作废" in res["reason"]
        assert res["config_epoch_start"] != res["config_epoch_end"]

    def test_concurrent_probes_do_not_interfere(self, client):
        set_config(client, mode="normal", drop_threshold=1000)
        out: dict[str, dict] = {}

        def worker(name, **kw):
            out[name] = run_probe(client, **kw)

        threads = [
            threading.Thread(target=worker, args=("a",), kwargs={"timeout_ms": 200}),
            threading.Thread(
                target=worker,
                args=("b",),
                kwargs={"min_size": 576, "max_size": 900, "timeout_ms": 200},
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        a, b = out["a"], out["b"]
        assert a["probe_id"] != b["probe_id"]
        assert a["status"] == "ok" and a["max_confirmed_size"] == 1000
        assert b["status"] == "ok" and b["max_confirmed_size"] == 900
        # 各自结论只由各自探测编号下的回包得出
        assert a["stray_replies"] == 0 and b["stray_replies"] == 0

    def test_probe_result_is_stored(self, client):
        res = run_probe(client)
        r = client.get(f"/probe/{res['probe_id']}")
        assert r.status_code == 200
        assert r.json()["probe_id"] == res["probe_id"]
        listing = client.get("/probes").json()
        assert any(p["probe_id"] == res["probe_id"] for p in listing)
        assert client.get("/probe/nope").status_code == 404

    def test_result_identical_when_fetched(self, client):
        # 当次答复与按 probe_id 查询给出同一份逐次结果和最大确认长度
        set_config(client, mode="normal", drop_threshold=1000)
        res = run_probe(client)
        r = client.get(f"/probe/{res['probe_id']}")
        assert r.status_code == 200
        assert r.json() == res
        assert r.json()["attempts"] == res["attempts"]
        assert r.json()["max_confirmed_size"] == res["max_confirmed_size"] == 1000

    def test_probe_request_validation(self, client):
        assert client.post("/probe", json={"min_size": 1000, "max_size": 576}).status_code == 422
        assert client.post("/probe", json={"min_size": 10}).status_code == 422
        assert client.post("/probe", json={"timeout_ms": 5}).status_code == 422


class TestDocs:
    def test_docs_and_openapi(self, client):
        assert client.get("/docs").status_code == 200
        spec = client.get("/openapi.json").json()
        assert "/echo/config" in spec["paths"]
        assert "/probe" in spec["paths"]


# ---------------------------------------------------------------- 内核收包时刻


class TestKernelTimestamp:
    def test_kernel_ts_fields_present(self, client):
        res = run_probe(client)
        assert res["kernel_ts_enabled"] is True
        assert res["late_replies"] == 0
        oks = [a for a in res["attempts"] if a["outcome"] == "ok"]
        assert oks, res["attempts"]
        for a in oks:
            # 每个成功探测都有内核收包时刻，RTT 由该时刻算出
            assert a["kernel_recv_at"] is not None
            assert a["rtt_ms"] is not None and 0 <= a["rtt_ms"] < 100

    def test_recv_time_unconfirmable_returns_undetermined(self, client, monkeypatch):
        # 匹配回包的收包时刻无法确认 → undetermined，保留已确认下界
        from app import netutil

        real_extract = netutil.extract_kernel_timestamp
        calls = {"n": 0}

        def fake_extract(ancdata):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_extract(ancdata)  # 首个回包时刻正常：988 字节确认成功
            return None  # 之后的回包时刻无法确认

        monkeypatch.setattr(netutil, "extract_kernel_timestamp", fake_extract)
        res = run_probe(client)
        assert res["status"] == "undetermined"
        assert "收包时刻" in res["reason"]
        # 默认范围首次二分 mid=988 已确认，下界保留
        assert res["max_confirmed_size"] == 988
        assert any(a["outcome"] == "undetermined" for a in res["attempts"])

    def test_platform_without_timestamps_returns_undetermined(self, client, monkeypatch):
        # 平台不支持内核收包时刻：如实上报，且收到匹配回包即终止
        from app import netutil

        monkeypatch.setattr(netutil, "enable_kernel_timestamps", lambda sock: False)
        monkeypatch.setattr(netutil, "extract_kernel_timestamp", lambda ancdata: None)
        res = run_probe(client)
        assert res["kernel_ts_enabled"] is False
        assert res["status"] == "undetermined"
        assert "收包时刻" in res["reason"]
        assert res["max_confirmed_size"] is None  # 首次探测即终止，尚无已确认下界


# ------------------------------------------------- 事件循环延迟 / 迟到回包场景


class _ThreadEcho:
    """独立线程里的阻塞式 UDP 回显端：不受被测事件循环卡顿影响。"""

    def __init__(self, delay_s: float = 0.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.delay_s = delay_s
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        self.sock.settimeout(0.05)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if self.delay_s:
                time.sleep(self.delay_s)
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def __enter__(self) -> "_ThreadEcho":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def _run_probe_against(port: int, stall: tuple[float, float] | None, **kw):
    """直接驱动探测引擎；stall=(t, d) 表示探测开始 t 秒后卡住事件循环 d 秒。"""
    from app.echo_server import EchoState
    from app.prober import Prober, ProbeRequest

    async def main():
        state = EchoState()
        prober = Prober(state, ("127.0.0.1", port))
        if stall is not None:
            at, duration = stall

            async def blocker():
                await asyncio.sleep(at)
                time.sleep(duration)  # 同步卡住事件循环：期间回包只到内核、无人读取

            task = asyncio.create_task(blocker())
            try:
                return await prober.probe(ProbeRequest(**kw))
            finally:
                await task
        return await prober.probe(ProbeRequest(**kw))

    return asyncio.run(main())


class TestEventLoopDelay:
    def test_in_time_reply_accepted_after_loop_stall(self):
        # 回包 ~1ms 即达内核，但事件循环被卡住 0.6s（超过 400ms 时限）才读包：
        # 应以内核收包时刻为准判成功，RTT 反映真实往返而非读包时刻
        with _ThreadEcho() as echo:
            res = _run_probe_against(
                echo.port, stall=(0.1, 0.6), min_size=576, max_size=576, timeout_ms=400
            )
        assert res.status == "ok"
        assert res.max_confirmed_size == 576
        att = res.attempts[0]
        assert att.outcome == "ok"
        assert att.kernel_recv_at is not None
        assert att.rtt_ms < 100  # 远小于事件循环卡顿的 600ms

    def test_late_reply_after_loop_stall_not_credited(self):
        # 回包 0.22s 才达内核（时限 150ms），事件循环 0.65s 后恢复读到它：
        # 迟到的匹配回包不得采信，计入 late_replies
        with _ThreadEcho(delay_s=0.2) as echo:
            res = _run_probe_against(
                echo.port, stall=(0.15, 0.5), min_size=576, max_size=576, timeout_ms=150
            )
        assert res.status == "undetermined"
        assert res.max_confirmed_size is None
        assert all(a.outcome != "ok" for a in res.attempts)
        assert res.late_replies >= 1
        first = res.attempts[0]
        assert first.outcome == "timeout"
        assert first.kernel_recv_at is not None  # 迟到包的内核收包时刻如实记录

    def test_late_reply_not_used_as_next_attempt(self):
        # 回显固定延迟 0.2s（时限 150ms）：上一次探测的迟到回包到达时，
        # 下一次探测正在等待——序号不符被丢弃，不得充当其回包
        with _ThreadEcho(delay_s=0.2) as echo:
            res = _run_probe_against(
                echo.port, stall=None, min_size=576, max_size=576, timeout_ms=150
            )
        assert res.status == "undetermined"  # 大包超时 + 小包复核也超时
        assert res.max_confirmed_size is None
        assert all(a.outcome != "ok" for a in res.attempts)
        purposes = [a.purpose for a in res.attempts]
        assert purposes == ["probe", "link-verify"]
        # 大包的迟到回包在小包复核窗口内到达，被记为不对应回包而非采信
        assert res.stray_replies >= 1
