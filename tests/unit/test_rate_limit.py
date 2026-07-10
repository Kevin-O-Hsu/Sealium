# tests/unit/test_rate_limit.py
"""速率限制器单元测试 + 429 集成测试（MEDIUM-002）。"""

from __future__ import annotations

import json
import tempfile
import pathlib
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from sealium.client.key_manager import ClientKeyManager
from sealium.common.crypto import RSAEncryptor
from sealium.server.app import create_app
from sealium.server.config import ServerConfig
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.rate_limit import InMemoryRateLimiter, NullRateLimiter


class TestInMemoryRateLimiter:
    def test_allows_up_to_max_then_denies(self):
        limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is False  # 第 4 次超限

    def test_independent_keys(self):
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.allow("a") is True
        assert limiter.allow("b") is True  # 不同 key 独立计数
        assert limiter.allow("a") is False

    def test_window_reset(self):
        clock = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=2, window_seconds=10, now_provider=lambda: clock[0]
        )
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is False
        clock[0] += 11  # 跨越窗口 -> 计数重置
        assert limiter.allow("ip") is True

    def test_invalid_args_raise(self):
        with pytest.raises(ValueError):
            InMemoryRateLimiter(max_requests=0, window_seconds=10)
        with pytest.raises(ValueError):
            InMemoryRateLimiter(max_requests=10, window_seconds=0)

    def test_null_limiter_always_allows(self):
        nl = NullRateLimiter()
        assert all(nl.allow("ip") for _ in range(1000))


def _build_app_with_limiter(server_keypair, storage, limiter):
    tmp = pathlib.Path(tempfile.mkdtemp())
    cfg = ServerConfig(
        project_root=tmp,
        database_path=tmp / "t.db",
        server_private_key_path=tmp / "p.pem",
        server_public_key_path=None,
        timestamp_tolerance_seconds=300,
        replay_cache_size=10000,
        host="127.0.0.1",
        port=8000,
        debug=False,
        cors_origins=["*"],
        api_prefix="/v1",
        activation_path="/activation",
        log_level="WARNING",
        log_format="%(message)s",
        rate_limit_enabled=False,  # 直接注入 limiter，不走配置
    )
    return create_app(
        config=cfg,
        encryptor=server_keypair,
        storage=storage,
        rate_limiter=limiter,
        now_provider=lambda: datetime(2026, 1, 1),
    )


class TestRateLimitIntegration:
    def test_over_limit_returns_429(self, server_keypair, storage):
        # 每窗口仅允许 2 次；第 3 次应被限流
        limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)
        app = _build_app_with_limiter(server_keypair, storage, limiter)
        pub = server_keypair.export_public_key().decode()

        def post():
            km = ClientKeyManager(pub)
            req = {
                "activation_code": "ghost",
                "machine_code": "m",
                "timestamp": int(datetime(2026, 1, 1).timestamp()),
                "nonce": "n",
            }
            pkt = km.build_encrypted_request(json.dumps(req).encode())
            with TestClient(app) as c:
                return c.post("/v1/activation", content=pkt)

        r1, r2, r3 = post(), post(), post()
        assert r1.status_code in (200, 400)
        assert r2.status_code in (200, 400)
        assert r3.status_code == 429
        assert r3.headers.get("retry-after") == "60"
