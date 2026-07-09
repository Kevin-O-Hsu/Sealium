# src/sealium/common/exceptions.py
"""
统一异常层次。

所有 Sealium 抛出的异常都继承自 :class:`SealiumError`，便于调用方
用 ``except SealiumError`` 一次性捕获本库错误，同时不会误伤标准库异常。
"""

from __future__ import annotations


class SealiumError(Exception):
    """所有 Sealium 异常的基类。"""


class CryptoError(SealiumError):
    """加解密相关错误（密钥加载、加解密失败、数据过长等）。"""


class ActivationError(SealiumError):
    """客户端激活流程错误（网络、加密、解析、nonce 校验失败等）。"""


class ConfigError(SealiumError):
    """配置无效（缺失文件、非法取值等）。"""
