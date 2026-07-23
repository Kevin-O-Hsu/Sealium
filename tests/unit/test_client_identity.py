# tests/unit/test_client_identity.py
"""真实客户端 IP 解析单元测试（HIGH-001）。

覆盖直连、受信单层/多层代理、伪造防护与缺省回退等全部分支。
"""

from __future__ import annotations

from starlette.datastructures import Headers

from sealium.server.client_identity import resolve_client_ip


class _Client:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    """最小 Request 替身：仅暴露 client.host 与 headers.get。"""

    def __init__(self, peer: str | None, xff: str | None = None) -> None:
        self.client = _Client(peer) if peer is not None else None
        raw = {"x-forwarded-for": xff} if xff is not None else {}
        self.headers = Headers(raw)


TRUSTED = ["127.0.0.1", "::1", "10.0.0.5"]


class TestDirectConnection:
    def test_direct_peer_returned_ignoring_xff(self):
        # 直连（对端不在受信代理）→ 返回对端，绝采信其 XFF（防伪造）
        req = _FakeRequest("203.0.113.9", xff="1.1.1.1")
        assert resolve_client_ip(req, TRUSTED) == "203.0.113.9"

    def test_direct_no_xff(self):
        req = _FakeRequest("203.0.113.9")
        assert resolve_client_ip(req, TRUSTED) == "203.0.113.9"


class TestTrustedProxy:
    def test_single_proxy_uses_xff(self):
        req = _FakeRequest("127.0.0.1", xff="203.0.113.10")
        assert resolve_client_ip(req, TRUSTED) == "203.0.113.10"

    def test_multi_hop_strips_trusted_tail(self):
        # 客户端 203.0.113.10 -> 受信代理 10.0.0.5 -> 受信代理 127.0.0.1 -> 应用
        # XFF 链右端是受信段，应剥离后取 203.0.113.10
        req = _FakeRequest("127.0.0.1", xff="203.0.113.10, 10.0.0.5")
        assert resolve_client_ip(req, TRUSTED) == "203.0.113.10"

    def test_trusted_proxy_no_xff_returns_peer(self):
        req = _FakeRequest("127.0.0.1")
        assert resolve_client_ip(req, TRUSTED) == "127.0.0.1"

    def test_all_trusted_chain_returns_peer(self):
        # XFF 全为受信段（罕见）→ 回退 TCP 对端
        req = _FakeRequest("127.0.0.1", xff="10.0.0.5, ::1")
        assert resolve_client_ip(req, TRUSTED) == "127.0.0.1"


class TestNoSpoofing:
    def test_untrusted_source_xff_ignored(self):
        # 攻击者直连伪造 XFF 链 → 必须忽略，用 TCP 对端（HOTSPOT-005）
        req = _FakeRequest("198.51.100.7", xff="1.2.3.4, 5.6.7.8")
        assert resolve_client_ip(req, TRUSTED) == "198.51.100.7"


class TestNoClient:
    def test_unknown_when_no_client(self):
        req = _FakeRequest(None)
        assert resolve_client_ip(req, TRUSTED) == "unknown"


class TestDefaultTrustedProxies:
    def test_default_trusts_loopback_only(self):
        # 默认只信回环：回环代理的 XFF 被采信
        assert resolve_client_ip(_FakeRequest("127.0.0.1", xff="203.0.113.20")) == "203.0.113.20"
        # 非回环代理不被默认信任：XFF 被忽略，返回对端
        assert resolve_client_ip(_FakeRequest("10.0.0.5", xff="203.0.113.20")) == "10.0.0.5"
