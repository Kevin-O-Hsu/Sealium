# src/sealium/server/client_identity.py
"""
真实客户端 IP 解析（HIGH-001 修复核心）。

问题
----
限流键不能直接用 ``request.client.host``（TCP 对端地址）。在推荐的生产部署
「Linux + 反向代理（nginx）」下，TCP 对端恒为代理自身 IP（如同机 nginx 的
``127.0.0.1``），导致所有外部真实客户端并入**同一个代理 IP 桶**，限流从
「每真实 IP 60 req/60s」退化为「全局共 60 req/60s」——一个仅持公开公钥的
攻击者即可耗尽全局额度，窗口内拒绝所有合法客户端激活（可用性 DoS）。

解法
----
受配置 ``trusted_proxies`` 控制的解析：仅当 TCP 对端 IP 在 ``trusted_proxies``
内时，才采信其写入的 ``X-Forwarded-For`` 头，并从头链右侧向左剥离所有受信代理
段，第一个非受信地址即为真实客户端 IP。

为什么不是「直接信任 X-Forwarded-For」
-------------------------------------
那样攻击者每请求换一个伪造的 XFF 值即可独享一个全新限流桶，限流形同虚设
（HOTSPOT-005）。约束在「只信任来自已知代理 IP 的 XFF」后，直连攻击者自报的
XFF 一律被忽略，伪造面消失。

默认 ``trusted_proxies`` 仅回环，覆盖「同机反代」这一默认推荐部署；跨机/容器
反代需在配置中显式加入反代所在 IP。
"""

from __future__ import annotations

from typing import Sequence

from fastapi import Request

# 与 ServerModel.trusted_proxies 默认值保持一致（同机反代场景）。
_DEFAULT_TRUSTED_PROXIES: tuple[str, ...] = ("127.0.0.1", "::1")


def resolve_client_ip(
    request: Request,
    trusted_proxies: Sequence[str] = _DEFAULT_TRUSTED_PROXIES,
) -> str:
    """返回用于限流分桶的真实客户端 IP。

    决策逻辑：

    1. TCP 对端**不在** ``trusted_proxies``：直接返回对端 IP。这是直连部署，
       或请求来自不受信来源——后者绝不能采信其可能伪造的 XFF。
    2. TCP 对端**在** ``trusted_proxies``：解析 ``X-Forwarded-For`` 头链，从
       右向左跳过所有受信代理段，第一个非受信地址即真实客户端 IP（标准做法，
       兼容多层受信代理链）；头缺失或全为受信段时回退 TCP 对端。

    :param request: FastAPI/Starlette 请求对象。
    :param trusted_proxies: 受信任代理 IP 集合（默认仅回环）。
    :return: 客户端 IP 字符串；无法确定时返回 ``"unknown"``。
    """
    peer = request.client.host if request.client else None
    if not peer:
        return "unknown"

    trusted = set(trusted_proxies)
    if peer not in trusted:
        return peer  # 直连 / 不受信来源：用 TCP 对端，忽略可能伪造的 XFF

    # 受信代理：从 XFF 头链右侧向左剥离受信段，第一个非受信即真实客户端
    xff = request.headers.get("x-forwarded-for", "")
    candidates = [part.strip() for part in xff.split(",") if part.strip()]
    for addr in reversed(candidates):
        if addr not in trusted:
            return addr
    return peer  # 受信代理但 XFF 缺失 / 全为受信段：回退对端
