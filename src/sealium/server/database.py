# src/sealium/server/database.py
"""
数据库操作：SQLite 底层 + 激活码表专用存储。

底层连接以 ``check_same_thread=False`` 打开，并用可重入锁保护所有操作，
因此可在 FastAPI 请求线程（含 ``TestClient`` 的 portal 线程）中安全使用。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sealium.common.fingerprint import MachineFingerprint, to_storage
from sealium.common.models import ActivationCode, ActivationStatus


class SQLiteDatabase:
    """SQLite 数据库底层操作（连接、事务、查询）。"""

    def __init__(self, db_path: str | Path) -> None:
        """
        :param db_path: SQLite 数据库文件路径。
        """
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    @property
    def connection(self) -> Optional[sqlite3.Connection]:
        return self._connection

    def connect(self) -> None:
        """建立连接；文件不存在则自动创建并初始化表结构。"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        db_exists = self.db_path.exists()
        # check_same_thread=False：允许在请求线程中使用（配合下方 _lock 保证并发安全）
        self._connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row  # 返回字典形式行
        self._connection.execute("PRAGMA foreign_keys = ON")
        if not db_exists:
            self.init_tables()
            # 新建的库文件收紧权限为仅属主可读写（LOW-002），避免多用户主机上被他人读取
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass  # 某些文件系统不支持 chmod，忽略而非崩溃

    def close(self) -> None:
        """关闭连接。"""
        with self._lock:
            if self._connection:
                self._connection.close()
                self._connection = None

    @contextmanager
    def transaction(self):
        """事务上下文管理器：正常退出提交，异常回滚。"""
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            try:
                yield
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """执行单条 SQL（无自动提交，需在事务中调用）。"""
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            return self._connection.execute(sql, params)

    def executemany(self, sql: str, params_list: list[tuple]) -> sqlite3.Cursor:
        """批量执行 SQL。"""
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            return self._connection.executemany(sql, params_list)

    def fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict[str, Any]]:
        """查询单行，返回字典或 None。"""
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            row = self._connection.execute(sql, params).fetchone()
        return dict(row) if row else None

    def fetch_all(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        """查询所有行，返回字典列表。"""
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            rows = self._connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def init_tables(self) -> None:
        """初始化数据库表结构。"""
        with self.transaction():
            self.execute(
                """
                CREATE TABLE IF NOT EXISTS activation_codes (
                    code TEXT PRIMARY KEY,
                    bound_machine_code TEXT,
                    activated_at TEXT,
                    expires_at TEXT,
                    features TEXT,
                    status INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def is_initialized(self) -> bool:
        """检查激活码表是否存在。"""
        try:
            return (
                self.fetch_one(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='activation_codes'"
                )
                is not None
            )
        except Exception:
            return False


class ActivationCodeStorage:
    """激活码表专用存储：CRUD + 序列化。"""

    def __init__(self, db: SQLiteDatabase) -> None:
        self.db = db

    # ---------- 序列化辅助 ----------
    @staticmethod
    def _serialize_features(features: list[str]) -> str:
        return json.dumps(features)

    @staticmethod
    def _deserialize_features(features_str: Optional[str]) -> list[str]:
        if not features_str:
            return []
        return json.loads(features_str)

    @staticmethod
    def _datetime_to_str(dt: Optional[datetime]) -> Optional[str]:
        return dt.isoformat() if dt is not None else None

    @staticmethod
    def _str_to_datetime(s: Optional[str]) -> Optional[datetime]:
        return datetime.fromisoformat(s) if s is not None else None

    @staticmethod
    def _encode_bound(mid: MachineFingerprint | None) -> str | None:
        """指纹 → DB TEXT（``None`` 透传）。"""
        return None if mid is None else to_storage(mid)

    @staticmethod
    def _decode_bound(raw: str | None) -> MachineFingerprint | None:
        """DB TEXT → 指纹（``None`` 透传）。"""
        if raw is None:
            return None
        return MachineFingerprint.from_dict(json.loads(raw))

    @staticmethod
    def _row_to_model(row: dict[str, Any]) -> ActivationCode:
        return ActivationCode(
            activation_code=row["code"],
            bound_machine_code=ActivationCodeStorage._decode_bound(row["bound_machine_code"]),
            activated_at=ActivationCodeStorage._str_to_datetime(row["activated_at"]),
            expires_at=ActivationCodeStorage._str_to_datetime(row["expires_at"]),
            features=ActivationCodeStorage._deserialize_features(row["features"]),
            status=ActivationStatus(row["status"]),
        )

    # ---------- CRUD ----------
    def create(self, activation_code: ActivationCode) -> None:
        """创建激活码记录。"""
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO activation_codes (
                    code, bound_machine_code, activated_at, expires_at, features, status
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    activation_code.activation_code,
                    ActivationCodeStorage._encode_bound(activation_code.bound_machine_code),
                    self._datetime_to_str(activation_code.activated_at),
                    self._datetime_to_str(activation_code.expires_at),
                    self._serialize_features(activation_code.features),
                    activation_code.status.value,
                ),
            )

    def get_by_code(self, code: str) -> Optional[ActivationCode]:
        """根据激活码查询。"""
        row = self.db.fetch_one("SELECT * FROM activation_codes WHERE code = ?", (code,))
        return self._row_to_model(row) if row else None

    def update_status(self, code: str, status: ActivationStatus) -> None:
        """更新激活码状态。"""
        with self.db.transaction():
            self.db.execute(
                "UPDATE activation_codes SET status = ? WHERE code = ?",
                (status.value, code),
            )

    def bind_machine_code(
        self, code: str, machine_code: str, activated_at: datetime
    ) -> bool:
        """
        原子绑定机器码并记录激活时间、置为已使用。

        通过 ``WHERE ... AND status = UNUSED`` 把“检查未使用 -> 置为已使用”
        压缩成单条 UPDATE，消除读-改-写竞态（HIGH-001）。多线程/多进程并发
        抢绑同一激活码时，只有第一个 UPDATE 会命中（``rowcount == 1``），
        其余落空（``rowcount == 0``）。

        :return: ``True`` 表示本次调用赢得了绑定（状态已从未用变为已用）；
                 ``False`` 表示已被他人抢先绑定，调用方应据此返回相应响应。
        """
        with self.db.transaction():
            cursor = self.db.execute(
                """
                UPDATE activation_codes
                SET bound_machine_code = ?, activated_at = ?, status = ?
                WHERE code = ? AND status = ?
                """,
                (
                    machine_code,
                    self._datetime_to_str(activated_at),
                    ActivationStatus.USED.value,
                    code,
                    ActivationStatus.UNUSED.value,
                ),
            )
            return cursor.rowcount == 1

    def update_expires_at(self, code: str, expires_at: datetime) -> None:
        """更新授权截止时间。"""
        with self.db.transaction():
            self.db.execute(
                "UPDATE activation_codes SET expires_at = ? WHERE code = ?",
                (self._datetime_to_str(expires_at), code),
            )

    def delete(self, code: str) -> None:
        """删除激活码记录。"""
        with self.db.transaction():
            self.db.execute("DELETE FROM activation_codes WHERE code = ?", (code,))

    def list_all(self) -> list[ActivationCode]:
        """列出所有激活码。"""
        return [self._row_to_model(row) for row in self.db.fetch_all("SELECT * FROM activation_codes")]
