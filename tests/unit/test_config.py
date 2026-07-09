# tests/unit/test_config.py
"""服务端配置单元测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from sealium.server.config import ServerConfig


class TestFromEnvDefaults:
    def test_defaults(self):
        cfg = ServerConfig.from_env(env={})
        assert cfg.api_prefix == "/v1"
        assert cfg.activation_path == "/activation"
        assert cfg.timestamp_tolerance_seconds == 300
        assert cfg.replay_cache_size == 10000
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 8000
        assert cfg.debug is False
        assert cfg.cors_origins == ["*"]
        assert cfg.server_public_key_path is None

    def test_activation_route(self):
        cfg = ServerConfig.from_env(env={})
        assert cfg.activation_route() == "/v1/activation"


class TestFromEnvOverrides:
    def test_env_override(self):
        cfg = ServerConfig.from_env(
            env={
                "API_PREFIX": "/api",
                "ACTIVATION_PATH": "/activate",
                "PORT": "9000",
                "DEBUG": "true",
                "TIME_STAMP_TOLERANCE_SECONDS": "60",
                "REPLAY_CACHE_SIZE": "500",
                "HOST": "127.0.0.1",
                "CORS_ORIGINS": "a.com,b.com",
                "SERVER_PUBLIC_KEY_PATH": "/tmp/pub.pem",
            }
        )
        assert cfg.api_prefix == "/api"
        assert cfg.activation_path == "/activate"
        assert cfg.activation_route() == "/api/activate"
        assert cfg.port == 9000
        assert cfg.debug is True
        assert cfg.timestamp_tolerance_seconds == 60
        assert cfg.replay_cache_size == 500
        assert cfg.host == "127.0.0.1"
        assert cfg.cors_origins == ["a.com", "b.com"]
        assert cfg.server_public_key_path == Path("/tmp/pub.pem")


class TestValidate:
    def test_missing_private_key_raises(self, tmp_path):
        cfg = ServerConfig.from_env(
            env={"SERVER_PRIVATE_KEY_PATH": str(tmp_path / "missing.pem")}
        )
        with pytest.raises(RuntimeError):
            cfg.validate()

    def test_present_private_key_ok(self, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text("dummy")
        cfg = ServerConfig.from_env(
            env={"SERVER_PRIVATE_KEY_PATH": str(key_file)}
        )
        cfg.validate()  # 不抛异常


class TestEnsureDirectories:
    def test_creates_parent_dirs(self, tmp_path):
        cfg = ServerConfig.from_env(
            env={
                "DATABASE_PATH": str(tmp_path / "sub" / "db.db"),
                "SERVER_PRIVATE_KEY_PATH": str(tmp_path / "keys" / "p.pem"),
            }
        )
        cfg.ensure_directories()
        assert (tmp_path / "sub").exists()
        assert (tmp_path / "keys").exists()
