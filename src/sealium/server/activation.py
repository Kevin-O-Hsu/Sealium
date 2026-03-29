# src/sealium/server/activation.py
"""
激活接口路由
实现 POST /activation 端点，处理客户端激活请求
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Set, Tuple
from fastapi import APIRouter, Request
from fastapi.responses import Response

from sealium.common import constants
from sealium.common.utils import Utils
from sealium.common.models import (
    ActivationRequest,
    ActivationResponse,
    ActivationStatus,
)
from sealium.common.crypto import RSAEncryptor
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.config import config


# ==================== 全局资源初始化 ====================
# 加载服务端私钥
def load_server_private_key() -> RSAEncryptor:
    """从文件加载服务端私钥"""
    if not config.SERVER_PRIVATE_KEY_PATH.exists():
        raise RuntimeError(f"服务端私钥文件不存在: {config.SERVER_PRIVATE_KEY_PATH}")
    with open(config.SERVER_PRIVATE_KEY_PATH, "rb") as f:
        pem_data = f.read()
    return RSAEncryptor.from_private_key_pem(pem_data)


# 加载客户端公钥
def load_client_public_key() -> RSAEncryptor:
    """从文件加载客户端公钥"""
    if not config.CLIENT_PUBLIC_KEY_PATH.exists():
        raise RuntimeError(f"客户端公钥文件不存在: {config.CLIENT_PUBLIC_KEY_PATH}")
    with open(config.CLIENT_PUBLIC_KEY_PATH, "rb") as f:
        pem_data = f.read()
    return RSAEncryptor.from_public_key_pem(pem_data)


_server_encryptor = load_server_private_key()  # 用于解密客户端请求
_client_encryptor = load_client_public_key()  # 用于加密响应给客户端

# 初始化数据库连接
_db = SQLiteDatabase(str(config.DATABASE_PATH))
_db.connect()
_db.init_tables()  # 确保表存在
_storage = ActivationCodeStorage(_db)

# 防重放：记录已使用的 (activation_code, nonce) 组合
_used_nonces: Set[Tuple[str, str]] = set()


# ==================== 辅助函数 ====================
def decrypt_request(raw_data: bytes) -> Dict[str, Any]:
    """解密客户端请求（使用服务端私钥）"""
    try:
        plain = _server_encryptor.decrypt(raw_data)
        return json.loads(plain.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"解密或解析请求失败: {e}")


def encrypt_response(data: Dict[str, Any]) -> bytes:
    """使用客户端公钥加密响应（固定公钥）"""
    try:
        plain = json.dumps(data).encode("utf-8")
        return _client_encryptor.encrypt(plain)
    except Exception as e:
        raise ValueError(f"加密响应失败: {e}")


def validate_timestamp(timestamp: int) -> bool:
    """校验时间戳是否在允许范围内"""
    now = Utils.get_current_timestamp()
    return abs(now - timestamp) <= config.TIME_STAMP_TOLERANCE_SECONDS


def check_replay(activation_code: str, nonce: str) -> bool:
    """检查是否为重放攻击"""
    key = (activation_code, nonce)
    if key in _used_nonces:
        return True
    _used_nonces.add(key)

    if len(_used_nonces) > config.REPLAY_CACHE_SIZE:
        _used_nonces.clear()
    return False


# ==================== 路由 ====================
router = APIRouter(prefix=config.API_PREFIX, tags=["activation"])


@router.post(config.ACTIVATION_PATH)
async def activate(request: Request) -> Response:
    """
    激活接口
    接收加密的激活请求，验证后返回加密的响应
    """
    # 1. 接收二进制数据
    raw_data = await request.body()
    if not raw_data:
        error_response = ActivationResponse.error("请求数据为空")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 2. 解密请求
    try:
        req_dict = decrypt_request(raw_data)
    except ValueError as e:
        error_response = ActivationResponse.error(f"解密失败: {str(e)}")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 3. 转换为请求对象
    try:
        activation_req = ActivationRequest.from_dict(req_dict)
    except Exception as e:
        error_response = ActivationResponse.error(f"请求格式错误: {str(e)}")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 4. 校验激活码格式
    if not Utils.validate_activation_code(activation_req.activation_code):
        error_response = ActivationResponse.error("激活码格式无效")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 5. 校验时间戳
    if not validate_timestamp(activation_req.timestamp):
        error_response = ActivationResponse.error("请求时间戳无效，请同步时间")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 6. 防重放检查
    if check_replay(activation_req.activation_code, activation_req.nonce):
        error_response = ActivationResponse.error("请求已被使用，请勿重复发送")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 7. 查询数据库获取激活码记录
    activation_record = _storage.get_by_code(activation_req.activation_code)
    if activation_record is None:
        error_response = ActivationResponse.error("激活码不存在")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 8. 检查激活码是否已被使用
    if activation_record.status == ActivationStatus.USED:
        # 如果已被使用，检查是否同一机器
        if activation_record.bound_machine_code == activation_req.machine_code:
            # 同一机器，直接返回成功（已激活）
            server_nonce = Utils.generate_nonce(16)
            success_response = ActivationResponse.success(
                authorized_until=(
                    activation_record.expires_at.strftime("%Y-%m-%d")
                    if activation_record.expires_at
                    else "永久"
                ),
                features=activation_record.features,
                nonce=server_nonce,
            )
            encrypted_response = encrypt_response(success_response.to_dict())
            return Response(
                content=encrypted_response, media_type="application/octet-stream"
            )
        else:
            # 不同机器，返回已被使用错误
            error_response = ActivationResponse.error("激活码已被其他设备使用")
            encrypted = encrypt_response(error_response.to_dict())
            return Response(content=encrypted, media_type="application/octet-stream")

    # 9. 检查是否过期
    if activation_record.expires_at and activation_record.expires_at < datetime.now():
        error_response = ActivationResponse.error("激活码已过期")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 10. 更新激活码：绑定机器码、激活时间、状态
    try:
        _storage.bind_machine_code(
            activation_req.activation_code, activation_req.machine_code, datetime.now()
        )
    except Exception as e:
        error_response = ActivationResponse.error(f"数据库更新失败: {str(e)}")
        encrypted = encrypt_response(error_response.to_dict())
        return Response(content=encrypted, media_type="application/octet-stream")

    # 11. 构造成功响应
    server_nonce = Utils.generate_nonce(16)
    success_response = ActivationResponse.success(
        authorized_until=(
            activation_record.expires_at.strftime("%Y-%m-%d")
            if activation_record.expires_at
            else "永久"
        ),
        features=activation_record.features,
        nonce=server_nonce,
    )

    # 12. 加密响应
    try:
        encrypted_response = encrypt_response(success_response.to_dict())
    except ValueError as e:
        error_response = ActivationResponse.error(f"加密响应失败: {str(e)}")
        encrypted_response = encrypt_response(error_response.to_dict())

    # 13. 返回成功响应
    return Response(content=encrypted_response, media_type="application/octet-stream")
