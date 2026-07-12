# tests/unit/test_generate_activation_codes.py
"""激活码生成脚本单元测试。"""

from __future__ import annotations

from datetime import datetime

import pytest

from sealium.common.models import ActivationStatus
from sealium.scripts.generate_activation_codes import (
    _parse_expires_at,
    generate_activation_code,
    generate_activation_codes,
)
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase


class TestGenerateActivationCode:
    def test_format(self):
        code = generate_activation_code()
        assert len(code) == 32
        assert all(c in "0123456789abcdef" for c in code)

    def test_uniqueness(self):
        codes = {generate_activation_code() for _ in range(100)}
        assert len(codes) == 100


class TestParseExpiresAt:
    def test_none_is_permanent(self):
        assert _parse_expires_at(None) is None

    def test_permanent_string(self):
        assert _parse_expires_at("permanent") is None
        assert _parse_expires_at("PERMANENT") is None

    def test_datetime_passthrough(self):
        dt = datetime(2026, 12, 31)
        assert _parse_expires_at(dt) == dt

    def test_date_string(self):
        assert _parse_expires_at("2026-12-31") == datetime(2026, 12, 31)

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            _parse_expires_at("not-a-date")

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError):
            _parse_expires_at(12345)


class TestGenerateActivationCodes:
    def test_generates_and_stores(self, tmp_path):
        db_path = tmp_path / "t.db"
        codes = generate_activation_codes(3, db_path=db_path)
        assert len(codes) == 3
        assert len(set(codes)) == 3

        db = SQLiteDatabase(db_path)
        db.connect()
        storage = ActivationCodeStorage(db)
        all_codes = storage.list_all()
        assert len(all_codes) == 3
        assert all(c.status == ActivationStatus.UNUSED for c in all_codes)
        db.close()

    def test_with_features_and_expiry(self, tmp_path):
        db_path = tmp_path / "t.db"
        codes = generate_activation_codes(
            1, expires_at="2026-12-31", features=["pro"], db_path=db_path
        )
        db = SQLiteDatabase(db_path)
        db.connect()
        storage = ActivationCodeStorage(db)
        record = storage.get_by_code(codes[0])
        assert record.features == ["pro"]
        assert record.expires_at == datetime(2026, 12, 31)
        db.close()

    def test_permanent_expiry_is_none(self, tmp_path):
        db_path = tmp_path / "t.db"
        codes = generate_activation_codes(1, db_path=db_path)
        db = SQLiteDatabase(db_path)
        db.connect()
        storage = ActivationCodeStorage(db)
        record = storage.get_by_code(codes[0])
        assert record.expires_at is None
        db.close()

    def test_appends_to_existing_database(self, tmp_path):
        db_path = tmp_path / "t.db"
        generate_activation_codes(2, db_path=db_path)
        generate_activation_codes(2, db_path=db_path)
        db = SQLiteDatabase(db_path)
        db.connect()
        storage = ActivationCodeStorage(db)
        assert len(storage.list_all()) == 4
        db.close()

    def test_generate_uses_configured_pepper(self, tmp_path, monkeypatch):
        """MEDIUM-002: generate 用配置的 code_hash_pepper，与激活服务一致。

        部署配了 SEALIUM_SECURITY__CODE_HASH_PEPPER 时，生成写入的哈希必须能被
        同 pepper 的服务端查到；用默认 pepper 的服务端查不到（证明 pepper 生效）。
        """
        from sealium.common.crypto import hash_activation_code
        import sys

        custom_pepper = "custom-deployment-pepper"

        class _FakeCfg:
            code_hash_pepper_secret = custom_pepper

        # 注意：sealium.scripts.__init__ 把同名函数导入包命名空间，遮蔽了子模块属性，
        # 故用 sys.modules 取真正的模块对象来 monkeypatch 其 get_config。
        gen_module = sys.modules["sealium.scripts.generate_activation_codes"]
        monkeypatch.setattr(gen_module, "get_config", lambda: _FakeCfg())

        db_path = tmp_path / "peppered.db"
        codes = generate_activation_codes(1, db_path=db_path)

        db = SQLiteDatabase(db_path)
        db.connect()
        same_pepper = ActivationCodeStorage(
            db, code_hasher=lambda c: hash_activation_code(c, custom_pepper)
        )
        default_pepper = ActivationCodeStorage(db)
        assert same_pepper.get_by_code(codes[0]) is not None  # 同 pepper 可查
        assert default_pepper.get_by_code(codes[0]) is None  # 默认 pepper 查不到
        db.close()
