# src/sealium/server/database.py
"""
数据库操作模块
提供 SQLite 底层操作类和激活码表专用存储类
"""

import json
import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

from sealium.common.models import ActivationStatus, ActivationCode


class SQLiteDatabase:
    """
    SQLite 数据库底层操作类
    管理连接、执行 SQL、事务等
    """

    def __init__(self, db_path: str):
        """
        初始化数据库连接

        :param db_path: SQLite 数据库文件路径
        """
        self.db_path = db_path
        self._connection = None

    def _ensure_database_directory(self) -> None:
        """确保数据库文件所在目录存在"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def connect(self) -> None:
        """建立数据库连接，如果数据库不存在则自动创建"""
        # 确保目录存在
        self._ensure_database_directory()

        # 检查数据库文件是否已存在
        db_exists = os.path.exists(self.db_path)

        # 连接数据库（如果文件不存在，SQLite 会自动创建）
        self._connection = sqlite3.connect(self.db_path)
        self._connection.row_factory = sqlite3.Row  # 返回字典形式行
        self._connection.execute("PRAGMA foreign_keys = ON")

        # 如果是新创建的数据库，初始化表结构
        if not db_exists:
            self.init_tables()

    def close(self) -> None:
        """关闭数据库连接"""
        if self._connection:
            self._connection.close()
            self._connection = None

    @contextmanager
    def transaction(self):
        """
        事务上下文管理器
        使用示例:
            with db.transaction():
                db.execute(...)
        """
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        try:
            yield
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def execute(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        """
        执行单条 SQL（无自动提交，需在事务中调用）

        :param sql: SQL 语句
        :param params: 参数元组
        :return: Cursor 对象
        """
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        return self._connection.execute(sql, params)

    def executemany(self, sql: str, params_list: List[Tuple]) -> sqlite3.Cursor:
        """
        执行批量 SQL

        :param sql: SQL 语句
        :param params_list: 参数元组列表
        :return: Cursor 对象
        """
        if self._connection is None:
            raise RuntimeError("数据库未连接")
        return self._connection.executemany(sql, params_list)

    def fetch_one(self, sql: str, params: Tuple = ()) -> Optional[Dict[str, Any]]:
        """
        查询单行记录

        :param sql: SQL 语句
        :param params: 参数元组
        :return: 字典或 None
        """
        cursor = self.execute(sql, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    def fetch_all(self, sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        """
        查询所有记录

        :param sql: SQL 语句
        :param params: 参数元组
        :return: 字典列表
        """
        cursor = self.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def init_tables(self) -> None:
        """初始化数据库表结构"""
        with self.transaction():
            self.execute("""
                CREATE TABLE IF NOT EXISTS activation_codes (
                    code TEXT PRIMARY KEY,
                    bound_machine_code TEXT,
                    activated_at TEXT,
                    expires_at TEXT,
                    features TEXT,
                    status INTEGER NOT NULL DEFAULT 0
                )
            """)

    def is_initialized(self) -> bool:
        """检查数据库是否已初始化（表是否存在）"""
        try:
            result = self.fetch_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='activation_codes'"
            )
            return result is not None
        except Exception:
            return False


class ActivationCodeStorage:
    """
    激活码表专用存储类
    提供激活码的增删改查操作
    """

    def __init__(self, db: SQLiteDatabase):
        """
        初始化存储类

        :param db: SQLiteDatabase 实例
        """
        self.db = db

    def _serialize_features(self, features: List[str]) -> str:
        """将功能列表序列化为 JSON 字符串"""
        return json.dumps(features)

    def _deserialize_features(self, features_str: Optional[str]) -> List[str]:
        """将 JSON 字符串反序列化为功能列表"""
        if not features_str:
            return []
        return json.loads(features_str)

    def _datetime_to_str(self, dt: Optional[datetime]) -> Optional[str]:
        """将 datetime 对象转换为 ISO 格式字符串"""
        if dt is None:
            return None
        return dt.isoformat()

    def _str_to_datetime(self, s: Optional[str]) -> Optional[datetime]:
        """将 ISO 格式字符串转换为 datetime 对象"""
        if s is None:
            return None
        return datetime.fromisoformat(s)

    def create(self, activation_code: ActivationCode) -> None:
        """
        创建激活码记录

        :param activation_code: ActivationCode 对象
        """
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO activation_codes (
                    code, bound_machine_code, activated_at, expires_at, features, status
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    activation_code.activation_code,
                    activation_code.bound_machine_code,
                    self._datetime_to_str(activation_code.activated_at),
                    self._datetime_to_str(activation_code.expires_at),
                    self._serialize_features(activation_code.features),
                    activation_code.status.value,
                )
            )

    def get_by_code(self, code: str) -> Optional[ActivationCode]:
        """
        根据激活码查询

        :param code: 激活码字符串
        :return: ActivationCode 对象或 None
        """
        row = self.db.fetch_one(
            "SELECT * FROM activation_codes WHERE code = ?",
            (code,)
        )
        if not row:
            return None
        return ActivationCode(
            activation_code=row["code"],
            bound_machine_code=row["bound_machine_code"],
            activated_at=self._str_to_datetime(row["activated_at"]),
            expires_at=self._str_to_datetime(row["expires_at"]),
            features=self._deserialize_features(row["features"]),
            status=ActivationStatus(row["status"]),
        )

    def update_status(self, code: str, status: ActivationStatus) -> None:
        """
        更新激活码状态

        :param code: 激活码字符串
        :param status: 新状态
        """
        with self.db.transaction():
            self.db.execute(
                "UPDATE activation_codes SET status = ? WHERE code = ?",
                (status.value, code)
            )

    def bind_machine_code(self, code: str, machine_code: str, activated_at: datetime) -> None:
        """
        绑定机器码并记录激活时间

        :param code: 激活码字符串
        :param machine_code: 机器码
        :param activated_at: 激活时间
        """
        with self.db.transaction():
            self.db.execute(
                """
                UPDATE activation_codes 
                SET bound_machine_code = ?, activated_at = ?, status = ? 
                WHERE code = ?
                """,
                (machine_code, self._datetime_to_str(activated_at), ActivationStatus.USED.value, code)
            )

    def update_expires_at(self, code: str, expires_at: datetime) -> None:
        """
        更新授权截止时间

        :param code: 激活码字符串
        :param expires_at: 新的截止时间
        """
        with self.db.transaction():
            self.db.execute(
                "UPDATE activation_codes SET expires_at = ? WHERE code = ?",
                (self._datetime_to_str(expires_at), code)
            )

    def delete(self, code: str) -> None:
        """
        删除激活码记录

        :param code: 激活码字符串
        """
        with self.db.transaction():
            self.db.execute(
                "DELETE FROM activation_codes WHERE code = ?",
                (code,)
            )

    def list_all(self) -> List[ActivationCode]:
        """
        列出所有激活码

        :return: ActivationCode 对象列表
        """
        rows = self.db.fetch_all("SELECT * FROM activation_codes")
        result = []
        for row in rows:
            result.append(ActivationCode(
                activation_code=row["code"],
                bound_machine_code=row["bound_machine_code"],
                activated_at=self._str_to_datetime(row["activated_at"]),
                expires_at=self._str_to_datetime(row["expires_at"]),
                features=self._deserialize_features(row["features"]),
                status=ActivationStatus(row["status"]),
            ))
        return result