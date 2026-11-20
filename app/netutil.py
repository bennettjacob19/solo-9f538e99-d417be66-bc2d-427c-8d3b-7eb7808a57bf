"""socket 工具：DF（Don't Fragment）位与逐包内核收包时刻。"""
from __future__ import annotations

import socket
import struct
from typing import Optional

# Linux 常量兜底（某些 Python 构建未导出）
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)

# struct timespec（CLOCK_REALTIME）：tv_sec + tv_nsec，原生模式兼容 32/64 位
_TIMESPEC = struct.Struct("@ll")


def set_dont_fragment(sock) -> bool:  # noqa: ANN001, ANN201
    """对 IPv4 UDP socket 设置 PMTUDISC_DO（DF=1）。

    设置后内核不会对本 socket 发出的报文做 IP 分片；
    若报文超过路径 MTU，发送将直接失败（EMSGSIZE），由上层按发送失败处理。
    返回是否设置成功（非 Linux 平台可能不支持，调用方应如实记录）。
    """
    if getattr(sock, "family", None) != socket.AF_INET:
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        return True
    except (OSError, AttributeError):
        return False


def enable_kernel_timestamps(sock) -> bool:  # noqa: ANN001, ANN201
    """启用 SO_TIMESTAMPNS：此后每个收到的数据报都附带内核收包时刻。

    内核在数据报到达协议栈时打戳（CLOCK_REALTIME），不受用户态
    事件循环调度延迟影响；需配合 recvmsg 读取控制消息（见
    :func:`extract_kernel_timestamp`）。返回是否设置成功
    （非 Linux 平台可能不支持，调用方应如实记录并降级处理）。
    """
    if getattr(sock, "family", None) != socket.AF_INET:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        return True
    except (OSError, AttributeError):
        return False


def extract_kernel_timestamp(ancdata) -> Optional[float]:  # noqa: ANN001
    """从 recvmsg 的 ancillary data 解析内核收包时刻。

    返回 Unix 秒（float，CLOCK_REALTIME，与 time.time() 同时基）；
    控制消息中没有 SO_TIMESTAMPNS 或数据不完整时返回 None。
    """
    for level, ctype, cdata in ancdata:
        if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS:
            if len(cdata) < _TIMESPEC.size:
                return None
            sec, nsec = _TIMESPEC.unpack(cdata[: _TIMESPEC.size])
            return sec + nsec / 1e9
    return None
