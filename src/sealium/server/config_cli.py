# src/sealium/server/config_cli.py
"""
配置管理 CLI（部署自检与模板生成）。

子命令
------
    init    在当前目录生成 sealium.toml 模板（已存在则跳过；--force 覆盖）
    show    脱敏打印当前生效配置
    check   加载并业务校验，退出码反映配置健康

用法
----
    python -m sealium.server.config_cli init
    python -m sealium.server.config_cli check
    python -m sealium.server.config_cli --config /etc/sealium/sealium.toml show

【开箱即用】Sealium 无需任何配置文件即可运行（默认值齐全）；本工具仅在需要
覆盖默认值时使用。模板作为代码常量内嵌，pip 安装后 ``init`` 一定可用，不依赖
仓库里的任何外部文件。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sealium.server.config import get_config

# ---------------------------------------------------------------------------
# init 生成的 sealium.toml 模板（与内置默认值一致，逐项注释）。
# 作为代码常量而非外部文件，确保 pip 安装后 `init` 一定可用——这是
# "pip 用户拿不到仓库根 .example 文件"问题的根本解法。
# ---------------------------------------------------------------------------
_SEALIUM_TOML_TEMPLATE = """\
# ==========================================================================
# Sealium 服务端配置文件
# ==========================================================================
# 由 `python -m sealium.server.config_cli init` 生成于当前目录。
# sealium.toml 已被 .gitignore 忽略，不会入库。
#
# 【这是可选配置】Sealium 开箱即用——不创建本文件也能直接运行：
#     python -m sealium.scripts.generate_keys
#     python -m sealium.scripts.generate_activation_codes --count 10
#     python -m sealium.server.run
# 仅当需要覆盖默认值时才编辑本文件。
#
# 配置优先级（高→低）：构造参数 > 环境变量 SEALIUM_* > .env > 本文件 > 默认值
# 敏感项（私钥口令）用环境变量，不要写进本文件：
#     export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=your-passphrase
# 相对路径相对本文件所在目录解析（整体搬迁部署目录不破坏路径）。
# ==========================================================================

[server]
host = "0.0.0.0"          # 生产建议 127.0.0.1（置于反向代理后）
port = 8000
debug = false             # 生产必须 false
api_prefix = "/v1"
activation_path = "/activation"

[paths]
database = "data/database.db"
private_key = "data/server_private.pem"
# public_key = "data/server_public.pem"   # 可选，仅调试用

[security]
timestamp_tolerance_seconds = 300
replay_cache_size = 10000
# private_key_passphrase：用环境变量 SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE，勿写此

[rate_limit]
enabled = true
max_requests = 60
window_seconds = 60

[machine_id]
threshold = 0.70
core_min = 3
spoof_max = 0.5

[logging]
level = "INFO"
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

[cors]
origins = ["*"]
"""


def _cmd_init(force: bool) -> int:
    """在当前目录生成 sealium.toml 模板。"""
    target = Path("sealium.toml").resolve()
    if target.exists() and not force:
        print(f"⚠️  已存在 {target}，未覆盖。用 --force 覆盖，或直接手动编辑。")
        return 1
    target.write_text(_SEALIUM_TOML_TEMPLATE, encoding="utf-8")
    print(f"✅ 已生成 {target}")
    print("   按需编辑后自检：python -m sealium.server.config_cli check")
    print("   无需配置也能直接启动：python -m sealium.server.run")
    return 0


def _cmd_show() -> int:
    cfg = get_config()
    print(json.dumps(cfg.safe_dump(), indent=2, ensure_ascii=False))
    return 0


def _cmd_check() -> int:
    try:
        cfg = get_config()
    except Exception as exc:  # 类型 / 范围 / 解析错误等
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
        description="Sealium 服务端配置管理（init / show / check）",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="TOML 配置文件路径（默认 ./sealium.toml；仅 show/check 读取）",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init", help="在当前目录生成 sealium.toml 模板")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的 sealium.toml")
    sub.add_parser("show", help="脱敏打印当前生效配置")
    sub.add_parser("check", help="加载并业务校验配置，退出码反映健康")
    args = parser.parse_args()

    # init 只写模板，不读配置；show/check 才需要加载（可能用 --config 指定文件）。
    if args.command == "init":
        sys.exit(_cmd_init(args.force))

    if args.config:
        os.environ["SEALIUM_CONFIG"] = args.config
        get_config.cache_clear()

    code = _cmd_show() if args.command == "show" else _cmd_check()
    sys.exit(code)


if __name__ == "__main__":
    main()
