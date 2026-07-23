# tests/server/test_proxy_rate_limit.py
"""反向代理部署下限流分桶的端到端测试（HIGH-001 / GRAY-001）。

复现并守护：经反向代理（X-Forwarded-For）时，不同真实客户端 IP 必须被分到
不同限流桶，而不是并入单一全局代理 IP 桶（旧缺陷下，一个攻击者即可耗尽全局
额度拒绝所有合法激活）。同时守护 HOTSPOT-005：不受信来源的 XFF 一律被忽略，
防止伪造绕过。

TestClient 的 ``request.client.host`` 恒为 ``"testclient"``，模拟「反代对端」；
将其纳入 ``trusted_proxies`` 即可让应用层采信 XFF 头做分桶。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from fastapi.testclient import TestClient

from sealium.client.key_manager import ClientKeyManager
from sealium.server.app import create_app
from sealium.server.config import (
    CorsModel,
    LoggingModel,
    PathsModel,
    SecurityModel,
    ServerConfig,
    ServerModel,
)
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase
from sealium.server.rate_limit import InMemoryRateLimiter

# TestClient 的 request.client.host 恒为此值，充当「反代对端」。
_PROXY_PEER = "testclient"


def _build_proxy_app(
    server_keypair, tmp_path: Path, trusted_proxies: list[str], limiter
):
    cfg = ServerConfig(
        server=ServerModel(
            host="127.0.0.1",
            port=8000,
            debug=False,
            api_prefix="/v1",
            activation_path="/activation",
            trusted_proxies=trusted_proxies,
        ),
        paths=PathsModel(database=tmp_path / "t.db", private_key=tmp_path / "p.pem"),
        security=SecurityModel(),
        logging=LoggingModel(level="WARNING", format="%(message)s"),
        cors=CorsModel(),
    )
    db = SQLiteDatabase(tmp_path / "t.db")
    db.connect()
    db.init_tables()
    storage = ActivationCodeStorage(db)
    return create_app(
        config=cfg,
        encryptor=server_keypair,
        storage=storage,
        rate_limiter=limiter,
        now_provider=lambda: datetime(2026, 1, 1),
    )


def _packet(public_pem: str) -> bytes:
    """构造一个结构合法的加密包（码不存在不影响限流阶段判定）。"""
    km = ClientKeyManager(public_pem)
    req = {
        "activation_code": "ghost",
        "machine_code": {},
        "timestamp": int(datetime(2026, 1, 1).timestamp()),
        "nonce": "n",
    }
    return km.build_encrypted_request(json.dumps(req).encode())


class TestProxyDistinctBuckets:
    def test_distinct_xff_ips_get_independent_buckets(self, server_keypair, tmp_path):
        """核心守护：不同真实 IP 经反代后落入独立限流桶（HIGH-001）。"""
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        app = _build_proxy_app(server_keypair, tmp_path, [_PROXY_PEER], limiter)
        pub = server_keypair.export_public_key().decode()
        with TestClient(app) as c:
            # IP-A 用满自身额度（每桶 1 次）
            r_a1 = c.post(
                "/v1/activation", content=_packet(pub),
                headers={"x-forwarded-for": "203.0.113.10"},
            )
            # IP-B 首次：与 A 不同桶 → 不应被 A 的额度牵连，非 429
            r_b1 = c.post(
                "/v1/activation", content=_packet(pub),
                headers={"x-forwarded-for": "203.0.113.20"},
            )
            # IP-A 第二次：超自身桶额度 → 429
            r_a2 = c.post(
                "/v1/activation", content=_packet(pub),
                headers={"x-forwarded-for": "203.0.113.10"},
            )
        assert r_a1.status_code != 429  # A 桶首次放行
        assert r_b1.status_code != 429  # B 桶独立放行（旧缺陷下此处会 429）
        assert r_a2.status_code == 429  # A 桶超限


class TestUntrustedProxyNoSpoofing:
    def test_untrusted_peer_xff_ignored_single_bucket(self, server_keypair, tmp_path):
        """HOTSPOT-005：对端不在 trusted_proxies 时，XFF 被忽略，并入对端单桶。

        同时复现「未把反代 IP 加入 trusted_proxies」时的退化——不同 XFF 仍共享
        同一对端桶，提示运维跨机反代必须配置 trusted_proxies。
        """
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        # 故意不信任 _PROXY_PEER
        app = _build_proxy_app(server_keypair, tmp_path, ["127.0.0.1"], limiter)
        pub = server_keypair.export_public_key().decode()
        with TestClient(app) as c:
            r1 = c.post(
                "/v1/activation", content=_packet(pub),
                headers={"x-forwarded-for": "203.0.113.10"},
            )
            r2 = c.post(
                "/v1/activation", content=_packet(pub),
                headers={"x-forwarded-for": "203.0.113.20"},  # 不同 XFF，但对端相同
            )
        assert r1.status_code != 429  # 对端桶首次
        assert r2.status_code == 429  # XFF 被忽略 → 同一对端桶超限
