# src/sealium/server/crypto_transport.py
"""
加密传输层：请求包解析 / 响应加密。

把"二进制包 <-> 业务字典"的转换从 HTTP 路由中抽离为纯函数，便于单测。

请求包：``[encrypted_aes_key] + [nonce] + [ciphertext] + [tag]``
响应包：``[nonce] + [ciphertext] + [tag]``
"""

from __future__ import annotations

import json

from sealium.common.constants import AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, RSA_KEY_SIZE
from sealium.common.crypto import AESEncryptor, RSAEncryptor


def parse_encrypted_request(
    raw_data: bytes, rsa_key_size: int = RSA_KEY_SIZE
) -> tuple[bytes, bytes, bytes, bytes]:
    """
    解析客户端请求包。

    :return: ``(encrypted_aes_key, nonce, ciphertext, tag)``。
    :raises ValueError: 数据包过短或缺认证标签。
    """
    rsa_len = rsa_key_size // 8
    if len(raw_data) < rsa_len + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise ValueError("请求数据包过短")

    encrypted_aes_key = raw_data[:rsa_len]
    nonce = raw_data[rsa_len : rsa_len + AES_GCM_NONCE_SIZE]
    rest = raw_data[rsa_len + AES_GCM_NONCE_SIZE :]
    if len(rest) < AES_GCM_TAG_SIZE:
        raise ValueError("请求数据包缺少认证标签")
    ciphertext = rest[:-AES_GCM_TAG_SIZE]
    tag = rest[-AES_GCM_TAG_SIZE:]
    return encrypted_aes_key, nonce, ciphertext, tag


def decrypt_request(
    server_encryptor: RSAEncryptor,
    encrypted_aes_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> tuple[bytes, dict]:
    """
    用服务端私钥解出 AES 密钥，再解密业务明文。

    :return: ``(aes_key, request_dict)``。
    """
    aes_key = server_encryptor.decrypt(encrypted_aes_key)
    plaintext = AESEncryptor.decrypt(aes_key, nonce, ciphertext, tag)
    request_dict = json.loads(plaintext.decode("utf-8"))
    return aes_key, request_dict


def encrypt_response(response_dict: dict, aes_key: bytes) -> bytes:
    """用会话 AES 密钥加密响应，组装响应包。"""
    plaintext = json.dumps(response_dict).encode("utf-8")
    nonce, ciphertext, tag = AESEncryptor.encrypt(aes_key, plaintext)
    return nonce + ciphertext + tag
