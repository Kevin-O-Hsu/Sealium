# src/sealium/server/routes/activation.py
"""
激活接口路由（薄 HTTP 层）。

只负责：限流 -> 读取请求体 -> 解密 -> 交给 ActivationService -> 加密响应。
业务规则全部在 :class:`ActivationService`，加密拆包在 ``crypto_transport``。
RSA 包长度从实际加载的私钥位数推导，而非硬编码 4096（HOTSPOT-001）。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from sealium.common.constants import MAX_ACTIVATION_BODY_BYTES
from sealium.common.crypto import RSAEncryptor
from sealium.common.models import ActivationRequest, ActivationResponse
from sealium.server.activation_service import ActivationService
from sealium.server.client_identity import resolve_client_ip
from sealium.server.crypto_transport import (
    decrypt_request,
    encrypt_response,
    parse_encrypted_request,
)
from sealium.server.deps import get_activation_service, get_rate_limiter, get_server_encryptor
from sealium.server.rate_limit import RateLimiter

logger = logging.getLogger("sealium.server.routes.activation")


def create_router(activation_path: str = "/activation") -> APIRouter:
    """创建激活路由（不含前缀，前缀由 ``app.include_router`` 注入）。"""
    router = APIRouter(tags=["activation"])

    @router.post(activation_path)
    async def activate(
        request: Request,
        encryptor: RSAEncryptor = Depends(get_server_encryptor),
        service: ActivationService = Depends(get_activation_service),
        rate_limiter: RateLimiter = Depends(get_rate_limiter),
    ) -> Response:
        # 0. 速率限制（MEDIUM-002）：按真实客户端 IP 聚合，超限直接 429。
        #    HIGH-001：反代部署下经 trusted_proxies 受控解析 X-Forwarded-For，
        #    否则 TCP 对端恒为代理 IP、所有限流并入全局单桶。
        client_ip = resolve_client_ip(request, request.app.state.config.server.trusted_proxies)
        if not rate_limiter.allow(client_ip):
            return Response(
                content=b"",
                status_code=429,
                headers={"Retry-After": str(rate_limiter.window_seconds)},
            )

        # 请求体大小硬上限（MEDIUM-001）：合法激活包 < 8KB，设 64KB 上限防内存耗尽 DoS。
        # 读前用 Content-Length 早拦截（不读入内存），读后用实际长度复检（防伪造/缺失头）。
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_ACTIVATION_BODY_BYTES:
                    return Response(content=b"", status_code=413)
            except ValueError:
                pass  # 非法 Content-Length，交由下方实际长度检查兜底
        raw_data = await request.body()
        if not raw_data:
            return Response(content=b"", status_code=400)
        if len(raw_data) > MAX_ACTIVATION_BODY_BYTES:
            return Response(content=b"", status_code=413)

        # 解密前的错误无法加密响应（尚无 AES 密钥），直接返回 400 空体
        try:
            # 包结构按实际私钥位数解析，避免硬编码 4096（HOTSPOT-001 / SMELL-001）
            parts = parse_encrypted_request(raw_data, rsa_key_size=encryptor.key_size)
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
                ActivationResponse.error(f"请求格式错误: {e}", nonce=None), aes_key
            )

        # 业务处理：兜底捕获意外异常，避免 500 泄漏堆栈 / 破坏协议（MEDIUM-004）
        try:
            result = service.process(activation_req)
        except Exception:
            logger.exception("激活处理发生未预期异常")
            return _encrypted_response(
                ActivationResponse.error("激活处理失败，请稍后重试", nonce=activation_req.nonce),
                aes_key,
            )
        return _encrypted_response(result, aes_key)

    return router


def _encrypted_response(response: ActivationResponse, aes_key: bytes) -> Response:
    return Response(
        content=encrypt_response(response.to_dict(), aes_key),
        media_type="application/octet-stream",
    )
