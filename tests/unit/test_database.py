# tests/unit/test_database.py
"""SQLite 底层与激活码存储单元测试。"""

from __future__ import annotations

from datetime import datetime

import pytest

from sealium.common.models import ActivationCode, ActivationStatus
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase


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
                    "INSERT INTO activation_codes (code, status) VALUES (?, ?)", ("c1", 0)
                )
                raise ValueError("boom")
        assert db.fetch_one("SELECT * FROM activation_codes WHERE code=?", ("c1",)) is None

    def test_transaction_commit(self, db: SQLiteDatabase):
        with db.transaction():
            db.execute(
                "INSERT INTO activation_codes (code, status) VALUES (?, ?)", ("c2", 0)
            )
        assert db.fetch_one("SELECT * FROM activation_codes WHERE code=?", ("c2",)) is not None

    def test_fetch_all(self, db: SQLiteDatabase):
        with db.transaction():
            db.execute("INSERT INTO activation_codes (code, status) VALUES (?, ?)", ("a", 0))
            db.execute("INSERT INTO activation_codes (code, status) VALUES (?, ?)", ("b", 0))
        assert len(db.fetch_all("SELECT * FROM activation_codes")) == 2

    def test_persistence_across_reopen(self, tmp_path):
        path = tmp_path / "persist.db"
        db1 = SQLiteDatabase(path)
        db1.connect()
        with db1.transaction():
            db1.execute("INSERT INTO activation_codes (code, status) VALUES (?, ?)", ("keep", 0))
        db1.close()
        db2 = SQLiteDatabase(path)
        db2.connect()
        assert db2.fetch_one("SELECT * FROM activation_codes WHERE code=?", ("keep",)) is not None
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

    def test_bind_machine_code_sets_fields(self, storage: ActivationCodeStorage):
        storage.create(ActivationCode(activation_code="c"))
        when = datetime(2026, 1, 1, 10, 0, 0)
        storage.bind_machine_code("c", "mc", when)
        got = storage.get_by_code("c")
        assert got.bound_machine_code == "mc"
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
        assert {c.activation_code for c in storage.list_all()} == {"a", "b"}

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
