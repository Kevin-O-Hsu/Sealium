# tests/unit/test_config.py
"""服务端配置单元测试（pydantic-settings + TOML 工业化配置）。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from sealium.common.fingerprint import MachineIdPolicy
from sealium.server.config import (
    CorsModel,
    LoggingModel,
    MachineIdModel,
    PathsModel,
    RateLimitModel,
    SecurityModel,
    ServerConfig,
    ServerModel,
    get_config,
)


@pytest.fixture
def clean_sealium_env(monkeypatch):
    """清除所有 SEALIUM_* 环境变量，保证测试基线干净（monkeypatch 自动还原）。"""
    for k in list(os.environ):
        if k.startswith("SEALIUM_"):
            monkeypatch.delenv(k, raising=False)


@pytest.fixture
def toml_writer(tmp_path, monkeypatch, clean_sealium_env):
    """写 TOML 到 tmp 并设 SEALIUM_CONFIG；返回(content)->Path 的写器。"""

    def _write(content: str) -> Path:
        p = tmp_path / "sealium.toml"
        p.write_text(content, encoding="utf-8")
        monkeypatch.setenv("SEALIUM_CONFIG", str(p))
        return p

    return _write


# ---------------------------------------------------------------------------
class TestDefaults:
    def test_defaults_no_toml(self, tmp_path, monkeypatch, clean_sealium_env):
        # 无 toml、无 env：全部走内置默认
        monkeypatch.setenv("SEALIUM_CONFIG", str(tmp_path / "nonexistent.toml"))
        cfg = ServerConfig()
        assert cfg.server.host == "0.0.0.0"
        assert cfg.server.port == 8000
        assert cfg.server.debug is False
        assert cfg.server.api_prefix == "/v1"
        assert cfg.server.activation_path == "/activation"
        assert cfg.security.timestamp_tolerance_seconds == 300
        assert cfg.security.replay_cache_size == 10000
        assert cfg.security.private_key_passphrase is None
        assert cfg.rate_limit.enabled is True
        assert cfg.rate_limit.max_requests == 60
        assert cfg.rate_limit.window_seconds == 60
        assert cfg.machine_id.threshold == 0.70
        assert cfg.machine_id.core_min == 3
        assert cfg.machine_id.spoof_max == 0.5
        assert cfg.logging.level == "INFO"
        assert cfg.cors.origins == ["*"]

    def test_activation_route(self, tmp_path, monkeypatch, clean_sealium_env):
        monkeypatch.setenv("SEALIUM_CONFIG", str(tmp_path / "nonexistent.toml"))
        cfg = ServerConfig()
        assert cfg.activation_route() == "/v1/activation"


class TestTomlLoading:
    def test_toml_overrides_defaults(self, toml_writer):
        path = toml_writer(
            """
[server]
host = "127.0.0.1"
port = 9000
debug = true

[paths]
database = "my.db"
private_key = "keys/priv.pem"

[security]
timestamp_tolerance_seconds = 120

[rate_limit]
max_requests = 100

[machine_id]
threshold = 0.80
core_min = 4
"""
        )
        cfg = ServerConfig()
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 9000
        assert cfg.server.debug is True
        assert cfg.security.timestamp_tolerance_seconds == 120
        assert cfg.rate_limit.max_requests == 100
        assert cfg.machine_id.threshold == 0.80
        assert cfg.machine_id.core_min == 4
        # 相对路径相对配置文件目录解析
        base = path.resolve().parent
        assert cfg.paths.database == base / "my.db"
        assert cfg.paths.private_key == base / "keys" / "priv.pem"

    def test_absolute_paths_preserved(self, toml_writer, tmp_path):
        abs_db = tmp_path / "abs" / "db.db"
        toml_writer(f'[paths]\ndatabase = "{abs_db.as_posix()}"\n')
        cfg = ServerConfig()
        assert cfg.paths.database == abs_db


class TestPriority:
    def test_env_overrides_toml(self, toml_writer, monkeypatch):
        toml_writer("[server]\nport = 8000\n")
        monkeypatch.setenv("SEALIUM_SERVER__PORT", "9000")
        monkeypatch.setenv("SEALIUM_SERVER__HOST", "10.0.0.1")
        cfg = ServerConfig()
        assert cfg.server.port == 9000
        assert cfg.server.host == "10.0.0.1"

    def test_init_kwargs_override_env(self, monkeypatch, clean_sealium_env):
        monkeypatch.setenv("SEALIUM_SERVER__PORT", "9000")
        cfg = ServerConfig(server=ServerModel(port=7000))
        assert cfg.server.port == 7000  # init > env


class TestSecretStr:
    def test_passphrase_via_env_not_leaked(self, monkeypatch, clean_sealium_env):
        monkeypatch.setenv("SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE", "s3cret-pw")
        cfg = ServerConfig()
        assert cfg.passphrase_secret == "s3cret-pw"
        # repr / SecretStr str / model_dump 均不暴露明文
        assert "s3cret-pw" not in repr(cfg)
        assert "s3cret-pw" not in str(cfg.security.private_key_passphrase)
        assert "s3cret-pw" not in str(cfg.model_dump())
        dump = cfg.safe_dump()
        assert dump["security"]["private_key_passphrase"] == "<set>"

    def test_no_passphrase(self, clean_sealium_env, tmp_path, monkeypatch):
        monkeypatch.setenv("SEALIUM_CONFIG", str(tmp_path / "none.toml"))
        cfg = ServerConfig()
        assert cfg.passphrase_secret is None
        assert cfg.safe_dump()["security"]["private_key_passphrase"] == "<unset>"


class TestRangeValidation:
    def test_port_out_of_range(self):
        with pytest.raises(ValidationError):
            ServerModel(port=0)
        with pytest.raises(ValidationError):
            ServerModel(port=99999)

    def test_threshold_out_of_range(self):
        with pytest.raises(ValidationError):
            MachineIdModel(threshold=5.0)
        with pytest.raises(ValidationError):
            MachineIdModel(threshold=-0.1)

    def test_spoof_max_out_of_range(self):
        with pytest.raises(ValidationError):
            MachineIdModel(spoof_max=2.0)

    def test_replay_cache_must_be_positive(self):
        with pytest.raises(ValidationError):
            SecurityModel(replay_cache_size=0)


class TestMachineIdPolicy:
    def test_conversion(self):
        cfg = ServerConfig(
            machine_id=MachineIdModel(threshold=0.9, core_min=2, spoof_max=0.3)
        )
        policy = cfg.machine_id_policy()
        assert isinstance(policy, MachineIdPolicy)
        assert policy.threshold == 0.9
        assert policy.core_min == 2
        assert policy.spoof_max == 0.3
        assert len(policy.weights) == 9  # DEFAULT_WEIGHTS 全部类别


class TestValidate:
    def test_missing_private_key_raises(self, tmp_path):
        cfg = ServerConfig(paths=PathsModel(private_key=tmp_path / "missing.pem"))
        with pytest.raises(RuntimeError):
            cfg.validate()

    def test_present_private_key_ok(self, tmp_path):
        key = tmp_path / "k.pem"
        key.write_text("dummy")
        cfg = ServerConfig(paths=PathsModel(private_key=key))
        cfg.validate()  # 不抛


class TestEnsureDirectories:
    def test_creates_parent_dirs(self, tmp_path):
        cfg = ServerConfig(
            paths=PathsModel(
                database=tmp_path / "sub" / "db.db",
                private_key=tmp_path / "keys" / "p.pem",
            )
        )
        cfg.ensure_directories()
        assert (tmp_path / "sub").exists()
        assert (tmp_path / "keys").exists()


class TestGetConfigCache:
    def test_lru_cache_singleton(self):
        get_config.cache_clear()
        a = get_config()
        b = get_config()
        assert a is b
        get_config.cache_clear()
        c = get_config()
        assert c is not a
        get_config.cache_clear()
