# src/sealium/server/config_cli.py
"""
配置检查 / 展示 CLI（工业级部署自检）。

    python -m sealium.server.config_cli check             # 加载 + 业务校验，退出码反映健康
    python -m sealium.server.config_cli show              # 脱敏打印生效配置
    python -m sealium.server.config_cli --config x.toml check

用途：部署前自检、CI 配置校验、运维排障。输出**绝不**包含私钥口令明文
（``show`` 经 :meth:`ServerConfig.safe_dump`，口令以 ``<set>``/``<unset>`` 表示）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from sealium.server.config import get_config


def _cmd_show() -> int:
    cfg = get_config()
    print(json.dumps(cfg.safe_dump(), indent=2, ensure_ascii=False))
    return 0


def _cmd_check() -> int:
    try:
        cfg = get_config()
    except Exception as exc:  # 配置加载失败：类型 / 范围 / 解析错误等（pydantic ValidationError 等）
        print(f"❌ 配置加载失败: {exc}", file=sys.stderr)
        return 1
    try:
        cfg.validate()  # 业务校验：私钥文件存在等
    except Exception as exc:
        print(f"❌ 配置业务校验失败: {exc}", file=sys.stderr)
        return 1
    print(f"✅ 配置正常（来源: {cfg.safe_dump()['config_file']}）")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sealium.server.config_cli",
        description="Sealium 服务端配置检查 / 脱敏展示",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="TOML 配置文件路径（默认 ./sealium.toml；等价于设 SEALIUM_CONFIG）",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show", help="脱敏打印当前生效配置")
    sub.add_parser("check", help="加载并业务校验配置，退出码反映配置健康")
    args = parser.parse_args()

    # 必须在 get_config() 首次调用前设置，确保加载指定文件
    if args.config:
        os.environ["SEALIUM_CONFIG"] = args.config
        get_config.cache_clear()

    code = _cmd_show() if args.command == "show" else _cmd_check()
    sys.exit(code)


if __name__ == "__main__":
    main()
