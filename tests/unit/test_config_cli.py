# tests/unit/test_config_cli.py
"""config_cli 模板生成（init）测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from sealium.server.config_cli import _cmd_init


@pytest.fixture
def cwd_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """把 cwd 切到临时目录（_cmd_init 写相对路径文件）。monkeypatch 自动恢复原 cwd。"""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestInit:
    def test_init_generates_both_files(self, cwd_tmp: Path):
        """init 同时生成 sealium.toml + .env（MEDIUM-003/005 文档同步）。"""
        assert _cmd_init(force=False) == 0
        assert (cwd_tmp / "sealium.toml").exists()
        assert (cwd_tmp / ".env").exists()

    def test_env_template_contains_secrets(self, cwd_tmp: Path):
        """.env 模板含两个 SecretStr 字段（含 MEDIUM-002 的 code_hash_pepper）。"""
        _cmd_init(force=False)
        env = (cwd_tmp / ".env").read_text(encoding="utf-8")
        assert "SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE" in env
        assert "SEALIUM_SECURITY__CODE_HASH_PEPPER" in env  # MEDIUM-002

    def test_toml_template_default_host_is_loopback(self, cwd_tmp: Path):
        """生成的 sealium.toml 默认 host 为回环（MEDIUM-005）。"""
        _cmd_init(force=False)
        toml = (cwd_tmp / "sealium.toml").read_text(encoding="utf-8")
        assert 'host = "127.0.0.1"' in toml

    def test_skips_existing_without_force(self, cwd_tmp: Path):
        """已存在且未 --force：跳过两项，返回 1。"""
        assert _cmd_init(force=False) == 0  # 首次生成
        rc = _cmd_init(force=False)  # 再次 → 跳过
        assert rc == 1
        assert (cwd_tmp / "sealium.toml").exists()
        assert (cwd_tmp / ".env").exists()

    def test_force_overwrites(self, cwd_tmp: Path):
        """--force 覆盖已存在文件。"""
        target = cwd_tmp / ".env"
        _cmd_init(force=False)
        target.write_text("HAND-EDITED\n", encoding="utf-8")
        assert _cmd_init(force=True) == 0
        assert "HAND-EDITED" not in target.read_text(encoding="utf-8")
