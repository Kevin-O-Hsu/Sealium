# src/sealium/server/config_cli.py
"""
配置管理 CLI（部署自检与模板生成）。

子命令
------
    init    在当前目录生成 sealium.toml + .env 模板（已存在则跳过该项；--force 覆盖）
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
# 【默认部署方式】Linux + 反向代理（nginx 等）——见 docs/server-guide.md。服务端默认
# 仅监听回环（同机反代转发）；反向代理跨机/容器时设 host = "0.0.0.0" 并务必置于反代
# + TLS 之后。Windows 作服务端部署时 0600 权限语义不生效，私钥务必口令加密。
#
# 配置优先级（高→低）：构造参数 > 环境变量 SEALIUM_* > .env > 本文件 > 默认值
# 敏感项（私钥口令）用环境变量，不要写进本文件：
#     export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=your-passphrase
# 相对路径相对本文件所在目录解析（整体搬迁部署目录不破坏路径）。
# ==========================================================================

[server]
# 默认 "127.0.0.1"（仅回环，同机反代转发）；反向代理跨机/容器时改为 "0.0.0.0" 或
# 内网 IP，并务必置于反代 + TLS 之后（MEDIUM-005）。
host = "127.0.0.1"
port = 8000
debug = false             # 生产必须 false
api_prefix = "/v1"
activation_path = "/activation"
# 受信任的代理 IP（HIGH-001）：仅当请求的 TCP 对端在此列表内时，限流才采信其
# 写入的 X-Forwarded-For 解析真实客户端 IP。默认仅回环（同机反代）；反向代理
# 跨机/容器时务必加入反代所在 IP，否则限流仍按代理 IP 聚合退化为全局单桶。
trusted_proxies = ["127.0.0.1", "::1"]
# Host 头白名单（LOW-006）：默认 ["*"] 不校验 Host；生产建议配具体域名（如
# ["activation.example.com"]）防裸暴露下 Host 投毒 / 路由混淆。
allowed_hosts = ["*"]

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


# ---------------------------------------------------------------------------
# init 生成的 .env 模板（敏感项 + 常用部署差异，逐项注释）。
# .env 已被 .gitignore 忽略，填入真实密钥后保持本地，绝不入库。
# ---------------------------------------------------------------------------
_ENV_TEMPLATE = """\
# ==========================================================================
# Sealium 敏感项与部署差异（.env）
# ==========================================================================
# 由 `python -m sealium.server.config_cli init` 生成于当前目录。
# .env 已被 .gitignore 忽略，不会入库——填入真实密钥后保持本地。
#
# .env 与环境变量同语义；优先级（高→低）：构造参数 > 环境变量 > .env > sealium.toml > 默认值。
# 结构化配置（端口/限流/策略等）建议放 sealium.toml；敏感项（口令/pepper）放这里。
# 完整字段说明见 docs/configuration.md。
# ==========================================================================

# ──────────────────────────────────────────────────────────────────────────
# 安全敏感项（务必改为你的随机值，切勿保留下面的占位符）
# ──────────────────────────────────────────────────────────────────────────

# 服务端私钥口令：需与 `generate_keys --passphrase` 一致。
# 未设则私钥明文落盘；Windows 下 0600 权限不生效，强烈建议设置。
SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=REPLACE_WITH_LONG_RANDOM_PASSPHRASE

# 激活码哈希 pepper（MEDIUM-002）：激活码以 HMAC-SHA256(code, pepper) 存储，DB 泄露也无法还原。
# 设为部署唯一随机串；**部署后不可变**——改它 = 已生成的激活码全部失效、需重新生成。
SEALIUM_SECURITY__CODE_HASH_PEPPER=REPLACE_WITH_DEPLOY_UNIQUE_RANDOM

# ──────────────────────────────────────────────────────────────────────────
# 部署差异（按需取消注释；结构化配置建议放 sealium.toml）
# ──────────────────────────────────────────────────────────────────────────

# 监听地址：默认 127.0.0.1（仅回环，同机反代转发）；反代跨机/容器时设 0.0.0.0。
# SEALIUM_SERVER__HOST=0.0.0.0
# 监听端口（默认 8000）
# SEALIUM_SERVER__PORT=8000
# 调试模式（生产必须 false）
# SEALIUM_SERVER__DEBUG=false

# 受信任代理 IP（HIGH-001）：反代跨机/容器时加入反代所在 IP，限流才按真实客户端
# IP 分桶（JSON 数组语法）。同机反代默认值 ["127.0.0.1","::1"] 无需设置。
# SEALIUM_SERVER__TRUSTED_PROXIES=["10.0.0.5","127.0.0.1","::1"]

# 限流（默认 60 req / 60 s 每 IP）
# SEALIUM_RATE_LIMIT__ENABLED=true
# SEALIUM_RATE_LIMIT__MAX_REQUESTS=60
# SEALIUM_RATE_LIMIT__WINDOW_SECONDS=60

# 时间戳容忍窗口（秒，默认 300）/ 防重放缓存容量（默认 10000）
# SEALIUM_SECURITY__TIMESTAMP_TOLERANCE_SECONDS=300
# SEALIUM_SECURITY__REPLAY_CACHE_SIZE=10000
"""


def _cmd_init(force: bool) -> int:
    """在当前目录生成 sealium.toml + .env 模板（已存在则跳过该项）。"""
    targets = (
        (Path("sealium.toml").resolve(), _SEALIUM_TOML_TEMPLATE),
        (Path(".env").resolve(), _ENV_TEMPLATE),
    )
    wrote: list[Path] = []
    skipped: list[Path] = []
    for path, template in targets:
        if path.exists() and not force:
            skipped.append(path)
            continue
        path.write_text(template, encoding="utf-8")
        wrote.append(path)
    if wrote:
        print("✅ 已生成：" + "、".join(str(p) for p in wrote))
        print("   编辑后自检：python -m sealium.server.config_cli check")
        print("   ⚠️  .env 含敏感占位符，务必改为你的随机值（.env 已被 .gitignore 忽略）。")
    if skipped:
        print("⚠️  已跳过（已存在，用 --force 覆盖）：" + "、".join(str(p) for p in skipped))
    return 0 if wrote else 1


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
    p_init = sub.add_parser("init", help="在当前目录生成 sealium.toml + .env 模板")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的 sealium.toml / .env")
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
