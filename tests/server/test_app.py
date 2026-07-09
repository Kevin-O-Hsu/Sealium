# tests/server/test_app.py
"""FastAPI 应用工厂与生命周期测试。"""

from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sealium.server.app import app as default_app, create_app
from sealium.server.config import ServerConfig


def _config(tmp_path, debug: bool = False) -> ServerConfig:
    return ServerConfig(
        project_root=tmp_path,
        database_path=tmp_path / "t.db",
        server_private_key_path=tmp_path / "p.pem",
        server_public_key_path=None,
        timestamp_tolerance_seconds=300,
        replay_cache_size=10000,
        host="127.0.0.1",
        port=8000,
        debug=debug,
        cors_origins=["*"],
        api_prefix="/v1",
        activation_path="/activation",
        log_level="WARNING",
        log_format="%(message)s",
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
    with TestClient(application) as test_client:
        resp = test_client.get("/debug/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "database_path" in body
        assert body["debug"] is True


def test_production_mode_hides_debug_endpoint(make_app, storage):
    application = make_app(storage)  # 默认 debug=False
    with TestClient(application) as test_client:
        assert test_client.get("/debug/config").status_code == 404
