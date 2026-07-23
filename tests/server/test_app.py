# tests/server/test_app.py
"""FastAPI 应用工厂与生命周期测试。"""

from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sealium.server.app import app as default_app, create_app
from sealium.server.config import (
    CorsModel,
    LoggingModel,
    PathsModel,
    SecurityModel,
    ServerConfig,
    ServerModel,
)


def _config(tmp_path, debug: bool = False) -> ServerConfig:
    return ServerConfig(
        server=ServerModel(
            host="127.0.0.1",
            port=8000,
            debug=debug,
            api_prefix="/v1",
            activation_path="/activation",
        ),
        paths=PathsModel(
            database=tmp_path / "t.db",
            private_key=tmp_path / "p.pem",
            public_key=None,
        ),
        security=SecurityModel(),
        logging=LoggingModel(level="WARNING", format="%(message)s"),
        cors=CorsModel(),
    )


def test_default_app_instance_exists():
    assert isinstance(default_app, FastAPI)


def test_factory_returns_fastapi(make_app, storage):
    application = make_app(storage)
    assert isinstance(application, FastAPI)


def test_lifespan_initializes_app_state(make_app, storage, server_keypair):
    application = make_app(storage)
    with TestClient(application) as test_client:
        assert application.state.server_encryptor is server_keypair
        assert application.state.activation_service is not None
        assert test_client.get("/health").status_code == 200


def test_debug_mode_exposes_debug_endpoint(server_keypair, storage, tmp_path):
    application = create_app(
        config=_config(tmp_path, debug=True),
        encryptor=server_keypair,
        storage=storage,
        now_provider=lambda: datetime(2026, 1, 1),
    )
    # LOW-004：/debug/config 仅限本机回环，用回环对端访问
    with TestClient(application, client=("127.0.0.1", 0)) as test_client:
        resp = test_client.get("/debug/config")
        assert resp.status_code == 200
        body = resp.json()
        assert body["server"]["debug"] is True
        assert "database" in body["paths"]
        # 脱敏：passphrase 永远不回显明文
        assert body["security"]["private_key_passphrase"] == "<unset>"


def test_debug_endpoint_rejects_non_loopback(server_keypair, storage, tmp_path):
    """LOW-004：/debug/config 仅限本机回环；非回环来源（如远程公网）返回 403。"""
    application = create_app(
        config=_config(tmp_path, debug=True),
        encryptor=server_keypair,
        storage=storage,
        now_provider=lambda: datetime(2026, 1, 1),
    )
    # 默认 TestClient 对端为 "testclient"（非回环），模拟远程访问
    with TestClient(application) as test_client:
        resp = test_client.get("/debug/config")
        assert resp.status_code == 403


class TestTrustedHostMiddleware:
    """LOW-006：allowed_hosts 配具体域名后启用 Host 头校验。"""

    @staticmethod
    def _app(server_keypair, storage, tmp_path):
        cfg = _config(tmp_path, debug=False)
        cfg.server.allowed_hosts = ["activation.example.com"]
        return create_app(
            config=cfg,
            encryptor=server_keypair,
            storage=storage,
            now_provider=lambda: datetime(2026, 1, 1),
        )

    def test_whitelisted_host_allowed(self, server_keypair, storage, tmp_path):
        application = self._app(server_keypair, storage, tmp_path)
        with TestClient(application, base_url="http://activation.example.com") as c:
            assert c.get("/health").status_code == 200

    def test_unknown_host_rejected(self, server_keypair, storage, tmp_path):
        application = self._app(server_keypair, storage, tmp_path)
        # 非白名单 Host → TrustedHostMiddleware 返回 400
        with TestClient(application, base_url="http://evil.example.com") as c:
            assert c.get("/health").status_code == 400

    def test_default_wildcard_accepts_any_host(self, make_app, storage):
        """默认 ["*"] 不校验，任意 Host 放行（零配置开箱不破坏）。"""
        application = make_app(storage)
        with TestClient(application, base_url="http://testserver") as c:
            assert c.get("/health").status_code == 200


def test_production_mode_hides_debug_endpoint(make_app, storage):
    application = make_app(storage)  # 默认 debug=False
    with TestClient(application) as test_client:
        assert test_client.get("/debug/config").status_code == 404
