# src/sealium/server/run.py
"""
服务端启动入口。

所有参数（host/port/log_level/debug）取自服务端配置，消除与配置的双份真相。

    python -m sealium.server.run
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
