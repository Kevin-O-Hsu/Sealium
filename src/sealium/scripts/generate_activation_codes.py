# src/sealium/scripts/generate_activation_codes.py
"""
激活码生成工具（程序内调用）
提供函数 generate_activation_codes 用于批量生成激活码并存入数据库
"""

import secrets
import os
from datetime import datetime
from typing import List, Optional, Union
from pathlib import Path

from sealium.common.models import ActivationCode, ActivationStatus
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.config import config


def generate_activation_codes(
        count: int,
        expires_at: Optional[Union[datetime, str]] = None,
        features: Optional[List[str]] = None,
        db_path: Optional[Union[str, Path]] = None,
) -> List[str]:
        """
    批量生成激活码并存入数据库

    :param count: 生成数量
    :param expires_at: 授权截止时间。可以是 datetime 对象，或字符串 "permanent" 表示永久，
                      或 None 表示永久。若为字符串日期如 "2026-12-31"，将自动解析。
    :param features: 功能列表，例如 ["premium", "enterprise"]
    :param db_path: 数据库路径，默认使用 ServerConfig 中的配置
    :return: 生成的激活码字符串列表
    """
        # 1. 处理参数默认值
        if features is None:
                features = []

        # 使用配置中的数据库路径（如果未指定）
        if db_path is None:
                db_path = config.DATABASE_PATH
        elif isinstance(db_path, str):
                db_path = Path(db_path)

        # 确保数据库目录存在
        db_path.parent.mkdir(parents=True, exist_ok=True)

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
        db = SQLiteDatabase(str(db_path))
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


def generate_activation_codes_with_output(
        count: int,
        expires_at: Optional[Union[datetime, str]] = None,
        features: Optional[List[str]] = None,
        db_path: Optional[Union[str, Path]] = None,
        output_file: Optional[Union[str, Path]] = None,
        print_codes: bool = True,
) -> List[str]:
        """
    批量生成激活码并可选输出到文件或控制台

    :param count: 生成数量
    :param expires_at: 授权截止时间
    :param features: 功能列表
    :param db_path: 数据库路径
    :param output_file: 输出文件路径（可选）
    :param print_codes: 是否打印到控制台
    :return: 生成的激活码字符串列表
    """
        # 生成激活码
        codes = generate_activation_codes(count, expires_at, features, db_path)

        # 打印到控制台
        if print_codes:
                print(f"\n成功生成 {len(codes)} 个激活码：")
                print("-" * 40)
                for i, code in enumerate(codes, 1):
                        print(f"{i:3d}. {code}")
                print("-" * 40)

                # 显示配置信息
                if expires_at:
                        expires_str = expires_at if isinstance(expires_at, str) else expires_at.strftime("%Y-%m-%d")
                        print(f"授权截止: {expires_str}")
                else:
                        print("授权截止: 永久")

                if features:
                        print(f"功能列表: {', '.join(features)}")
                print()

        # 输出到文件
        if output_file:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                        for code in codes:
                                f.write(f"{code}\n")
                print(f"✅ 激活码已保存到: {output_path}")

        return codes


# 命令行入口（当直接运行脚本时）
if __name__ == "__main__":
        import argparse

        parser = argparse.ArgumentParser(description="批量生成激活码")
        parser.add_argument("--count", type=int, default=10, help="生成数量（默认：10）")
        parser.add_argument("--expires", type=str, default="permanent",
                            help="授权截止日期，格式 YYYY-MM-DD 或 permanent（永久）")
        parser.add_argument("--features", type=str, default="",
                            help="授权功能列表，逗号分隔，例如 premium,enterprise")
        parser.add_argument("--db", type=str, help="数据库路径（默认使用配置文件中的路径）")
        parser.add_argument("--output", type=str, help="输出文件路径（可选）")
        parser.add_argument("--no-print", action="store_true", help="不打印到控制台")

        args = parser.parse_args()

        # 解析功能列表
        features = None
        if args.features:
                features = [f.strip() for f in args.features.split(",") if f.strip()]

        # 生成激活码
        generate_activation_codes_with_output(
                count=args.count,
                expires_at=args.expires,
                features=features,
                db_path=args.db,
                output_file=args.output,
                print_codes=not args.no_print,
        )