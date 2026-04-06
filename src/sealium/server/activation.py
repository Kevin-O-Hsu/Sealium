# src/sealium/server/activation.py
"""
激活接口路由
实现 POST /activation 端点，处理客户端激活请求
"""

import json
from datetime import datetime
from typing import Dict, Any, Set, Tuple
from fastapi import APIRouter, Request
from fastapi.responses import Response

from sealium.common.utils import Utils
from sealium.common.models import (
    ActivationRequest,
    ActivationResponse,
    ActivationStatus,
)
from sealium.common.crypto import RSAEncryptor, AESEncryptor
from sealium.common.constants import RSA_KEY_SIZE, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.config import config


# ==================== 全局资源初始化 ====================
def load_server_private_key() -> RSAEncryptor:
    """从文件加载服务端私钥"""
    if not config.SERVER_PRIVATE_KEY_PATH.exists():
        raise RuntimeError(f"服务端私钥文件不存在: {config.SERVER_PRIVATE_KEY_PATH}")
    with open(config.SERVER_PRIVATE_KEY_PATH, "rb") as f:
        pem_data = f.read()
    return RSAEncryptor.from_private_key_pem(pem_data)


_server_encryptor = load_server_private_key()

_db = SQLiteDatabase(str(config.DATABASE_PATH))
_db.connect()
_db.init_tables()
_storage = ActivationCodeStorage(_db)

_used_nonces: Set[Tuple[str, str]] = set()


# ==================== 辅助函数 ====================
def parse_encrypted_request(raw_data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    rsa_encrypted_len = RSA_KEY_SIZE // 8
    if len(raw_data) < rsa_encrypted_len + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise ValueError("请求数据包过短")
    encrypted_aes_key = raw_data[:rsa_encrypted_len]
    nonce = raw_data[rsa_encrypted_len : rsa_encrypted_len + AES_GCM_NONCE_SIZE]
    rest = raw_data[rsa_encrypted_len + AES_GCM_NONCE_SIZE :]
    if len(rest) < AES_GCM_TAG_SIZE:
        raise ValueError("请求数据包缺少认证标签")
    ciphertext = rest[:-AES_GCM_TAG_SIZE]
    tag = rest[-AES_GCM_TAG_SIZE:]
    return encrypted_aes_key, nonce, ciphertext, tag


def decrypt_request_and_get_key(
    encrypted_aes_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes
) -> Tuple[bytes, Dict[str, Any]]:
    """解密请求，返回 (aes_key, request_dict)"""
    aes_key = _server_encryptor.decrypt(encrypted_aes_key)
    plaintext = AESEncryptor.decrypt(aes_key, nonce, ciphertext, tag)
    req_dict = json.loads(plaintext.decode("utf-8"))
    return aes_key, req_dict


def encrypt_response_with_aes(response_dict: Dict[str, Any], aes_key: bytes) -> bytes:
    plaintext = json.dumps(response_dict).encode("utf-8")
    nonce, ciphertext, tag = AESEncryptor.encrypt(aes_key, plaintext)
    return nonce + ciphertext + tag


def validate_timestamp(timestamp: int) -> bool:
    now = Utils.get_current_timestamp()
    return abs(now - timestamp) <= config.TIME_STAMP_TOLERANCE_SECONDS


def check_replay(activation_code: str, nonce: str) -> bool:
    key = (activation_code, nonce)
    if key in _used_nonces:
        return True
    _used_nonces.add(key)
    if len(_used_nonces) > config.REPLAY_CACHE_SIZE:
        _used_nonces.clear()
    return False


router = APIRouter(prefix=config.API_PREFIX, tags=["activation"])


@router.post(config.ACTIVATION_PATH)
async def activate(request: Request) -> Response:
    raw_data = await request.body()
    if not raw_data:
        return Response(content=b"", status_code=400)

    try:
        enc_aes_key, nonce, ciphertext, tag = parse_encrypted_request(raw_data)
    except ValueError:
        return Response(content=b"", status_code=400)

    try:
        aes_key, req_dict = decrypt_request_and_get_key(
            enc_aes_key, nonce, ciphertext, tag
        )
    except Exception:
        return Response(content=b"", status_code=400)

    try:
        activation_req = ActivationRequest.from_dict(req_dict)
    except Exception as e:
        error_resp = ActivationResponse.error(f"请求格式错误: {str(e)}")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 校验激活码格式
    if not Utils.validate_activation_code(activation_req.activation_code):
        error_resp = ActivationResponse.error("激活码格式无效")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 校验时间戳
    if not validate_timestamp(activation_req.timestamp):
        error_resp = ActivationResponse.error("请求时间戳无效，请同步时间")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 防重放检查
    if check_replay(activation_req.activation_code, activation_req.nonce):
        error_resp = ActivationResponse.error("请求已被使用，请勿重复发送")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 查询数据库
    activation_record = _storage.get_by_code(activation_req.activation_code)
    if activation_record is None:
        error_resp = ActivationResponse.error("激活码不存在")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 检查状态
    if activation_record.status == ActivationStatus.USED:
        if activation_record.bound_machine_code == activation_req.machine_code:
            # 同一机器，返回成功
            success_resp = ActivationResponse.success(
                authorized_until=(
                    activation_record.expires_at.strftime("%Y-%m-%d")
                    if activation_record.expires_at
                    else "永久"
                ),
                features=activation_record.features,
                nonce=activation_req.nonce,
            )
            encrypted_resp = encrypt_response_with_aes(success_resp.to_dict(), aes_key)
            return Response(
                content=encrypted_resp, media_type="application/octet-stream"
            )
        else:
            error_resp = ActivationResponse.error("激活码已被其他设备使用")
            encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
            return Response(
                content=encrypted_error, media_type="application/octet-stream"
            )

    # 检查过期
    if activation_record.expires_at and activation_record.expires_at < datetime.now():
        error_resp = ActivationResponse.error("激活码已过期")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 绑定机器码
    try:
        _storage.bind_machine_code(
            activation_req.activation_code, activation_req.machine_code, datetime.now()
        )
    except Exception as e:
        error_resp = ActivationResponse.error(f"数据库更新失败: {str(e)}")
        encrypted_error = encrypt_response_with_aes(error_resp.to_dict(), aes_key)
        return Response(content=encrypted_error, media_type="application/octet-stream")

    # 成功响应
    success_resp = ActivationResponse.success(
        authorized_until=(
            activation_record.expires_at.strftime("%Y-%m-%d")
            if activation_record.expires_at
            else "永久"
        ),
        features=activation_record.features,
        nonce=activation_req.nonce,
    )
    encrypted_resp = encrypt_response_with_aes(success_resp.to_dict(), aes_key)
    return Response(content=encrypted_resp, media_type="application/octet-stream")
