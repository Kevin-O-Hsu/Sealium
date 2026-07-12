# src/sealium/scripts/__init__.py
"""脚本工具：密钥生成、激活码生成。

为避免 ``python -m sealium.scripts.<name>`` 触发 RuntimeWarning（父包在 ``__init__``
顶层 import 子模块，会与 ``-m`` 把同名子模块作为 ``__main__`` 重新执行相冲突，官方
提示 "may result in unpredictable behaviour"），这里采用 PEP 562 惰性导入，与
``sealium.server.__init__`` 保持一致——仅在显式访问时才加载子模块。
"""

from __future__ import annotations

__all__ = ["generate_activation_codes", "generate_key_pair"]


def __getattr__(name: str):
    # 惰性导入：访问 generate_key_pair / generate_activation_codes 时才 import 对应模块。
    if name == "generate_key_pair":
        from sealium.scripts.generate_keys import generate_key_pair

        return generate_key_pair
    if name == "generate_activation_codes":
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        return generate_activation_codes
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
