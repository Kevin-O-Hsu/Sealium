# tests/unit/test_database.py
"""SQLite 底层与激活码存储单元测试。"""

from __future__ import annotations

from datetime import datetime

import pytest

from sealium.common.constants import CODE_HASH_PEPPER_DEFAULT
from sealium.common.crypto import hash_activation_code
from sealium.common.fingerprint import to_storage
from sealium.common.models import ActivationCode, ActivationStatus
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase


def _hash(code: str) -> str:
    """测试用哈希（与 storage 默认 code_hasher 同 pepper，MEDIUM-002）。"""
    return hash_activation_code(code, CODE_HASH_PEPPER_DEFAULT)


class TestSQLiteDatabase:
    def test_connect_initializes_tables(self, tmp_path):
        db = SQLiteDatabase(tmp_path / "x.db")
        db.connect()
        assert db.is_initialized()
        db.close()

    def test_connect_creates_parent_dirs(self, tmp_path):
        db = SQLiteDatabase(tmp_path / "nested" / "deep" / "x.db")
        db.connect()
        assert (tmp_path / "nested" / "deep" / "x.db").exists()
        db.close()

    def test_execute_before_connect_raises(self, tmp_path):
        db = SQLiteDatabase(tmp_path / "x.db")
        with pytest.raises(RuntimeError):
            db.execute("SELECT 1")

    def test_transaction_rollback(self, db: SQLiteDatabase):
        with pytest.raises(ValueError):
            with db.transaction():
                db.execute(
                    "INSERT INTO activation_codes (code_hash, status) VALUES (?, ?)", ("c1", 0)
                )
                raise ValueError("boom")
        assert db.fetch_one("SELECT * FROM activation_codes WHERE code_hash=?", ("c1",)) is None

    def test_transaction_commit(self, db: SQLiteDatabase):
        with db.transaction():
            db.execute(
                "INSERT INTO activation_codes (code_hash, status) VALUES (?, ?)", ("c2", 0)
            )
        assert db.fetch_one("SELECT * FROM activation_codes WHERE code_hash=?", ("c2",)) is not None

    def test_fetch_all(self, db: SQLiteDatabase):
        with db.transaction():
            db.execute("INSERT INTO activation_codes (code_hash, status) VALUES (?, ?)", ("a", 0))
            db.execute("INSERT INTO activation_codes (code_hash, status) VALUES (?, ?)", ("b", 0))
        assert len(db.fetch_all("SELECT * FROM activation_codes")) == 2

    def test_persistence_across_reopen(self, tmp_path):
        path = tmp_path / "persist.db"
        db1 = SQLiteDatabase(path)
        db1.connect()
        with db1.transaction():
            db1.execute("INSERT INTO activation_codes (code_hash, status) VALUES (?, ?)", ("keep", 0))
        db1.close()
        db2 = SQLiteDatabase(path)
        db2.connect()
        assert db2.fetch_one("SELECT * FROM activation_codes WHERE code_hash=?", ("keep",)) is not None
        db2.close()


class TestActivationCodeStorage:
    def test_create_and_get(self, storage: ActivationCodeStorage):
        storage.create(
            ActivationCode(activation_code="code1", features=["x"], status=ActivationStatus.UNUSED)
        )
        got = storage.get_by_code("code1")
        assert got is not None
        assert got.features == ["x"]
        assert got.status == ActivationStatus.UNUSED

    def test_get_missing_returns_none(self, storage: ActivationCodeStorage):
        assert storage.get_by_code("nope") is None

    def test_duplicate_create_raises(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="dup"))
        with pytest.raises(Exception):  # UNIQUE 约束
            storage.create(ActivationCode(activation_code="dup"))

    def test_update_status(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c"))
        storage.update_status("c", ActivationStatus.USED)
        assert storage.get_by_code("c").status == ActivationStatus.USED

    def test_bind_machine_code_sets_fields(self, storage: ActivationCodeStorage, make_fingerprint):
        storage.create(ActivationCode(activation_code="c"))
        when = datetime(2026, 1, 1, 10, 0, 0)
        fp = make_fingerprint("mc")
        storage.bind_machine_code("c", to_storage(fp), when)
        got = storage.get_by_code("c")
        assert got.bound_machine_code == fp
        assert got.activated_at == when
        assert got.status == ActivationStatus.USED

    def test_update_expires_at(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c", expires_at=datetime(2026, 1, 1)))
        storage.update_expires_at("c", datetime(2030, 1, 1))
        assert storage.get_by_code("c").expires_at == datetime(2030, 1, 1)

    def test_delete(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c"))
        storage.delete("c")
        assert storage.get_by_code("c") is None

    def test_list_all(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="a"))
        storage.create(ActivationCode(activation_code="b"))
        # DB 读回的 activation_code 是哈希值（明文不可得，MEDIUM-002）
        assert {c.activation_code for c in storage.list_all()} == {_hash("a"), _hash("b")}

    def test_features_serialization_roundtrip(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c", features=["pro", "ent"]))
        assert storage.get_by_code("c").features == ["pro", "ent"]

    def test_expires_at_datetime_roundtrip(self, storage: ActivationCodeStorage):
        dt = datetime(2026, 6, 15, 10, 30, 0)
        storage.create(ActivationCode(activation_code="c", expires_at=dt))
        assert storage.get_by_code("c").expires_at == dt

    def test_null_features_deserialize_to_empty(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c"))
        assert storage.get_by_code("c").features == []

    def test_code_stored_as_hash_not_plaintext(self, storage: ActivationCodeStorage):
        """MEDIUM-002: DB 只存 code_hash，绝不存明文 code。"""
        storage.create(ActivationCode(activation_code="secret-123"))
        rows = storage.db.fetch_all("SELECT * FROM activation_codes")
        assert len(rows) == 1
        row = rows[0]
        assert "code_hash" in row
        assert "code" not in row  # 无明文 code 列
        assert row["code_hash"] == _hash("secret-123")
        assert row["code_hash"] != "secret-123"  # 存的不是明文

    def test_different_pepper_isolates_codes(self, db: SQLiteDatabase):
        """MEDIUM-002: 不同 pepper 产出不同 hash，互相查不到（per-deployment 隔离）。"""
        s_a = ActivationCodeStorage(
            db, code_hasher=lambda c: hash_activation_code(c, "pepper-a")
        )
        s_a.create(ActivationCode(activation_code="same"))
        s_b = ActivationCodeStorage(
            db, code_hasher=lambda c: hash_activation_code(c, "pepper-b")
        )
        assert s_b.get_by_code("same") is None  # 不同 pepper → 不同 hash → 查不到
        assert s_a.get_by_code("same") is not None
