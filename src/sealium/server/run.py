# src/sealium/server/run.py
"""
服务端启动入口。

所有参数（host/port/log_level/debug）取自服务端配置，消除与配置的双份真相。

    python -m sealium.server.run

部署安全提示（INFO-002 / INFO-003）
----------------------------------
* 默认监听 ``0.0.0.0``，设计为置于反向代理 / 防火墙之后对外暴露，请勿在裸金属
  上直接公网开放。
* 本进程默认为明文 HTTP；业务负载已由 RSA+AES 混合加密端到端保护，但建议仍在上
  游反向代理终止 TLS（并加 HSTS），以隐藏时序 / 错误码等元信息。
* 多 worker 部署（``uvicorn --workers N`` / gunicorn）时，防重放与限流均为进程内
  计数；若需全局一致，请注入共享后端（如 Redis）。
"""

from __future__ import annotations

import uvicorn

from sealium.server.config import config

if __name__ == "__main__":
    uvicorn.run(
        "sealium.server.app:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
