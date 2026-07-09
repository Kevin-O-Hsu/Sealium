# src/sealium/__init__.py
"""
Sealium —— 安全许可证密钥生成、软件激活与硬件绑定。

导入本包零副作用：不发起网络请求、不读取硬件、不连接数据库、不打印日志。
服务端组件（FastAPI 应用等）需显式从 ``sealium.server`` 导入。
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("sealium")
except PackageNotFoundError:  # 源码直接运行、未安装时
    __version__ = "0.0.0+unknown"

from sealium.client.activator import Activator, ActivationError
from sealium.client.key_manager import ClientKeyManager
from sealium.common.crypto import AESEncryptor, RSAEncryptor
from sealium.common.models import (
    ActivationCode,
    ActivationRequest,
    ActivationResponse,
    ActivationStatus,
)

__all__ = [
    "__version__",
    # client
    "Activator",
    "ActivationError",
    "ClientKeyManager",
    # common
    "RSAEncryptor",
    "AESEncryptor",
    "ActivationCode",
    "ActivationRequest",
    "ActivationResponse",
    "ActivationStatus",
]
