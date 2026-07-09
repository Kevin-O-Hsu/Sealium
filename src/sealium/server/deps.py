# src/sealium/server/deps.py
"""
FastAPI 依赖：从应用状态取出运行时组件（私钥加密器、激活服务）。

这些组件在应用生命周期（lifespan）启动时组装并挂到 ``app.state``，路由通过
依赖注入获取，从而保持路由与具体装配解耦。
"""

from __future__ import annotations

from fastapi import Depends, Request

from sealium.common.crypto import RSAEncryptor
from sealium.server.activation_service import ActivationService


def get_server_encryptor(request: Request) -> RSAEncryptor:
    """获取服务端 RSA 加密器（持有私钥）。"""
    return request.app.state.server_encryptor


def get_activation_service(request: Request) -> ActivationService:
    """获取激活业务服务。"""
    return request.app.state.activation_service


# 便于测试一次性取到两者
def get_activation_dependencies(
    encryptor: RSAEncryptor = Depends(get_server_encryptor),
    service: ActivationService = Depends(get_activation_service),
) -> tuple[RSAEncryptor, ActivationService]:
    """同时获取加密器与激活服务。"""
    return encryptor, service
