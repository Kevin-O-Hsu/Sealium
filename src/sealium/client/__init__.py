# src/sealium/client/__init__.py
"""客户端：激活器与密钥管理。"""

from sealium.client.activator import Activator, ActivationError
from sealium.client.key_manager import ClientKeyManager

__all__ = ["Activator", "ActivationError", "ClientKeyManager"]
