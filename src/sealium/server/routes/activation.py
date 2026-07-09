# src/sealium/server/routes/activation.py
"""
激活接口路由（薄 HTTP 层）。

只负责：读取请求体 -> 解密 -> 交给 ActivationService -> 加密响应。
业务规则全部在 :class:`ActivationService`，加密拆包在 ``crypto_transport``。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from sealium.common.crypto import RSAEncryptor
from sealium.common.models import ActivationRequest, ActivationResponse
from sealium.server.activation_service import ActivationService
from sealium.server.crypto_transport import (
    decrypt_request,
    encrypt_response,
    parse_encrypted_request,
)
from sealium.server.deps import get_activation_service, get_server_encryptor


def create_router(activation_path: str = "/activation") -> APIRouter:
    """创建激活路由（不含前缀，前缀由 ``app.include_router`` 注入）。"""
    router = APIRouter(tags=["activation"])

    @router.post(activation_path)
    async def activate(
        request: Request,
        encryptor: RSAEncryptor = Depends(get_server_encryptor),
        service: ActivationService = Depends(get_activation_service),
    ) -> Response:
        raw_data = await request.body()
        if not raw_data:
            return Response(content=b"", status_code=400)

        # 解密前的错误无法加密响应（尚无 AES 密钥），直接返回 400 空体
        try:
            parts = parse_encrypted_request(raw_data)
        except ValueError:
            return Response(content=b"", status_code=400)

        try:
            aes_key, req_dict = decrypt_request(encryptor, *parts)
        except Exception:
            return Response(content=b"", status_code=400)

        try:
            activation_req = ActivationRequest.from_dict(req_dict)
        except Exception as e:
            return _encrypted_response(
                ActivationResponse.error(f"请求格式错误: {e}"), aes_key
            )

        result = service.process(activation_req)
        return _encrypted_response(result, aes_key)

    return router


def _encrypted_response(response: ActivationResponse, aes_key: bytes) -> Response:
    return Response(
        content=encrypt_response(response.to_dict(), aes_key),
        media_type="application/octet-stream",
    )
