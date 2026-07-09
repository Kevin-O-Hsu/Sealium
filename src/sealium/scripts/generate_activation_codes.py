# src/sealium/scripts/generate_activation_codes.py
"""
激活码生成工具：批量生成激活码并写入数据库。

既可作为库函数调用（``generate_activation_codes``），也可作为命令行脚本运行。
"""

from __future__ import annotations

import argparse
import secrets
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from sealium.common.constants import ACTIVATION_CODE_BYTES
from sealium.common.models import ActivationCode, ActivationStatus
from sealium.server.config import config
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase


def generate_activation_code() -> str:
    """生成单个激活码（32 个十六进制字符，128 位随机）。"""
    return secrets.token_hex(ACTIVATION_CODE_BYTES)


def _parse_expires_at(
    expires_at: Optional[Union[datetime, str]],
) -> Optional[datetime]:
    """解析授权截止时间：datetime / 'YYYY-MM-DD' / 'permanent' / None(永久)。"""
    if expires_at is None or (
        isinstance(expires_at, str) and expires_at.lower() == "permanent"
    ):
        return None
    if isinstance(expires_at, datetime):
        return expires_at
    if isinstance(expires_at, str):
        try:
            return datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError:
            raise ValueError(
                f"无效的日期格式: {expires_at}，应为 YYYY-MM-DD 或 'permanent'"
            )
    raise TypeError("expires_at 必须为 datetime 对象、'permanent' 字符串或 None")


def generate_activation_codes(
    count: int,
    expires_at: Optional[Union[datetime, str]] = None,
    features: Optional[List[str]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> List[str]:
    """
    批量生成激活码并存入数据库。

    :param count: 生成数量。
    :param expires_at: 授权截止时间（datetime / 'YYYY-MM-DD' / 'permanent' / None=永久）。
    :param features: 功能列表，如 ["premium", "enterprise"]。
    :param db_path: 数据库路径，默认使用服务端配置。
    :return: 生成的激活码字符串列表。
    """
    if features is None:
        features = []
    path = Path(db_path) if db_path is not None else config.database_path
    path.parent.mkdir(parents=True, exist_ok=True)

    expires_datetime = _parse_expires_at(expires_at)

    db = SQLiteDatabase(path)
    db.connect()
    storage = ActivationCodeStorage(db)

    generated: List[str] = []
    try:
        for _ in range(count):
            code = generate_activation_code()
            storage.create(
                ActivationCode(
                    activation_code=code,
                    expires_at=expires_datetime,
                    features=features,
                    status=ActivationStatus.UNUSED,
                )
            )
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
    """批量生成激活码，并可选输出到文件或控制台。"""
    codes = generate_activation_codes(count, expires_at, features, db_path)

    if print_codes:
        print(f"\n成功生成 {len(codes)} 个激活码：")
        print("-" * 40)
        for i, code in enumerate(codes, 1):
            print(f"{i:3d}. {code}")
        print("-" * 40)

        if expires_at:
            expires_str = (
                expires_at
                if isinstance(expires_at, str)
                else expires_at.strftime("%Y-%m-%d")
            )
            print(f"授权截止: {expires_str}")
        else:
            print("授权截止: 永久")

        if features:
            print(f"功能列表: {', '.join(features)}")
        print()

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for code in codes:
                f.write(f"{code}\n")
        print(f"✅ 激活码已保存到: {output_path}")

    return codes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="批量生成激活码")
    parser.add_argument("--count", type=int, default=10, help="生成数量（默认：10）")
    parser.add_argument(
        "--expires",
        type=str,
        default="permanent",
        help="授权截止日期，格式 YYYY-MM-DD 或 permanent（永久）",
    )
    parser.add_argument(
        "--features",
        type=str,
        default="",
        help="授权功能列表，逗号分隔，例如 premium,enterprise",
    )
    parser.add_argument("--db", type=str, help="数据库路径（默认使用配置文件中的路径）")
    parser.add_argument("--output", type=str, help="输出文件路径（可选）")
    parser.add_argument("--no-print", action="store_true", help="不打印到控制台")

    args = parser.parse_args()

    features_list = (
        [f.strip() for f in args.features.split(",") if f.strip()] if args.features else None
    )

    generate_activation_codes_with_output(
        count=args.count,
        expires_at=args.expires,
        features=features_list,
        db_path=args.db,
        output_file=args.output,
        print_codes=not args.no_print,
    )
