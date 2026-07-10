# src/sealium/server/__init__.py
"""服务端：FastAPI 应用、激活服务、数据库与配置。

为保持 ``import sealium.server.*`` 零副作用（不读配置文件、不触发应用装配），
``create_app`` 与 ``ActivationService`` 采用惰性导入（PEP 562 ``__getattr__``），
仅在显式访问时才加载对应模块。``ServerConfig`` / ``get_config`` 直接导出，
其源模块本身在导入时不做任何 I/O。
"""

from __future__ import annotations

from sealium.server.config import ServerConfig, get_config

__all__ = ["create_app", "ServerConfig", "get_config", "ActivationService"]


def __getattr__(name: str):
    # 惰性导入：访问 create_app / ActivationService 时才 import 对应模块，
    # 避免 import sealium.server（或其子模块）即触发 app 装配与配置文件读取。
    if name == "create_app":
        from sealium.server.app import create_app

        return create_app
    if name == "ActivationService":
        from sealium.server.activation_service import ActivationService

        return ActivationService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
