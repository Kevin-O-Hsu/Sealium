# src/sealium/scripts/generate_activation_codes.py
"""
激活码生成工具（程序内调用）
提供函数 generate_activation_codes 用于批量生成激活码并存入数据库
"""

import os
import secrets
from datetime import datetime
from typing import List, Optional, Union

from sealium.common.models import ActivationCode, ActivationStatus
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage


def generate_activation_codes(
    count: int,
    expires_at: Optional[Union[datetime, str]] = None,
    features: Optional[List[str]] = None,
    db_path: Optional[str] = None,
) -> List[str]:
    """
    批量生成激活码并存入数据库

    :param count: 生成数量
    :param expires_at: 授权截止时间。可以是 datetime 对象，或字符串 "permanent" 表示永久，
                      或 None 表示永久。若为字符串日期如 "2026-12-31"，将自动解析。
    :param features: 功能列表，例如 ["premium", "enterprise"]
    :param db_path: 数据库路径，默认使用环境变量 DATABASE_PATH，否则 "./data/sealium.db"
    :return: 生成的激活码字符串列表
    """
    # 1. 处理参数默认值
    if features is None:
        features = []
    if db_path is None:
        db_path = 'I:/Programming/Sealium/data/database.db'

    # 2. 解析截止时间
    expires_datetime = None
    if expires_at is None or (isinstance(expires_at, str) and expires_at.lower() == "permanent"):
        expires_datetime = None
    elif isinstance(expires_at, datetime):
        expires_datetime = expires_at
    elif isinstance(expires_at, str):
        try:
            expires_datetime = datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"无效的日期格式: {expires_at}，应为 YYYY-MM-DD 或 'permanent'")
    else:
        raise TypeError("expires_at 必须为 datetime 对象、'permanent' 字符串或 None")

    # 3. 连接数据库（自动创建目录和表）
    db = SQLiteDatabase(db_path)
    db.connect()
    storage = ActivationCodeStorage(db)

    generated = []
    try:
        for _ in range(count):
            code = secrets.token_hex(16)  # 32 字符，128位
            activation = ActivationCode(
                activation_code=code,
                bound_machine_code=None,
                activated_at=None,
                expires_at=expires_datetime,
                features=features,
                status=ActivationStatus.UNUSED,
            )
            storage.create(activation)
            generated.append(code)
    finally:
        db.close()

    return generated


# 如果直接运行脚本，则使用默认参数生成示例激活码（便于测试）
if __name__ == "__main__":
    # 示例：生成 5 个永久有效的激活码，无功能限制
    codes = generate_activation_codes(10)
    print("生成的激活码：")
    for c in codes:
        print(f"  {c}")

    # 示例：生成带截止日期和功能的激活码
    # codes = generate_activation_codes(3, expires_at="2027-12-31", features=["premium"])
    # print(codes)