# src/sealium/server/routes/__init__.py
"""服务端 HTTP 路由。"""

from sealium.server.routes.activation import create_router

__all__ = ["create_router"]
