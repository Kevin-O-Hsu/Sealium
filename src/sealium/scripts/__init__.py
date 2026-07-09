# src/sealium/scripts/__init__.py
"""脚本工具：密钥生成、激活码生成。"""

from sealium.scripts.generate_activation_codes import generate_activation_codes
from sealium.scripts.generate_keys import generate_key_pair

__all__ = ["generate_activation_codes", "generate_key_pair"]
