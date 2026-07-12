# src/sealium/server/run.py
"""
服务端启动入口。

所有参数（host/port/log_level/debug）取自服务端配置，消除与配置的双份真相。

    python -m sealium.server.run
    python -m sealium.server.run --config /etc/sealium/sealium.toml

部署安全提示（MEDIUM-005 / MEDIUM-006）
---------------------------------------
* 默认监听 ``127.0.0.1``（仅回环）——安全默认，强制对外暴露需显式配置。同机反向
  代理直接转发即可；反向代理在另一台机器或容器内时，于 ``sealium.toml`` 设
  ``[server] host = "0.0.0.0"``（或内网 IP），并务必置于反代 + TLS 之后。
* 本进程默认为明文 HTTP；业务负载已由 RSA+AES 混合加密端到端保护，但元信息（时序
  / 状态码 / 包大小）仍明文可见，应在上游反向代理终止 TLS（并加 HSTS）隐藏。
* 多 worker 部署（``uvicorn --workers N`` / gunicorn）时，防重放与限流均为进程内
  计数；若需全局一致，**必须**注入共享后端（如 Redis）。
"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from sealium.server.config import get_config


# 视为回环的 host：不出网卡，无需"裸暴露"告警（MEDIUM-005）。
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _warn_bare_exposure(cfg) -> None:
    """host 显式放开到非回环时，显著告警明文 HTTP 裸暴露风险（MEDIUM-005）。"""
    host = cfg.server.host
    if cfg.server.debug or host in _LOOPBACK_HOSTS:
        return
    print(
        f"⚠️  WARNING: 监听 {host}（非回环）且本进程为明文 HTTP。请确保已置于反向代理"
        " + TLS 之后，否则请求元信息（时序 / 状态码 / 包大小）对网络明文可见。",
        file=sys.stderr,
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="启动 Sealium 激活服务")
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="TOML 配置文件路径（默认 ./sealium.toml；等价于设 SEALIUM_CONFIG 环境变量）",
    )
    args = parser.parse_args()

    if args.config:
        # 必须在 get_config() 首次调用前设置，确保加载指定文件
        os.environ["SEALIUM_CONFIG"] = args.config
        get_config.cache_clear()

    cfg = get_config()
    _warn_bare_exposure(cfg)
    # 注：请求体大小上限（MEDIUM-001）不在 uvicorn 配置——uvicorn 无此参数，body 大小限制
    # 本属 ASGI 应用层职责（见 https://uvicorn.dev/settings/）。已在路由层 activation.py 用
    # Content-Length 头 + 实际长度双重 413 拦截实现，并由 test_oversized_body_returns_413 守护。
    uvicorn.run(
        "sealium.server.app:app",
        host=cfg.server.host,
        port=cfg.server.port,
        reload=cfg.server.debug,
        log_level=cfg.logging.level.lower(),
    )


if __name__ == "__main__":
    main()
