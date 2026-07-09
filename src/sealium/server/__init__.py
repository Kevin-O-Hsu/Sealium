# src/sealium/server/__init__.py
"""服务端：FastAPI 应用、激活服务、数据库与配置。"""

from sealium.server.activation_service import ActivationService
from sealium.server.app import create_app
from sealium.server.config import ServerConfig, config

__all__ = ["create_app", "ServerConfig", "config", "ActivationService"]
