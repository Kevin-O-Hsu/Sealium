# src/sealium/client/key_manager.py
"""
客户端密钥管理（仅持有服务端公钥，无私钥）。

负责混合加密的数据包组装与拆解：

请求包 ``[encrypted_aes_key (512B)] + [nonce (12B)] + [ciphertext] + [tag (16B)]``
    * 生成临时 AES-256 密钥 -> AES-GCM 加密业务明文
    * 服务端 RSA 公钥加密该 AES 密钥
    * 拼接为单个二进制包

响应包 ``[nonce (12B)] + [ciphertext] + [tag (16B)]``
    * 用同一把临时 AES 密钥解密
"""

from __future__ import annotations

from typing import Optional

from sealium.common.constants import AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE
from sealium.common.crypto import AESEncryptor, RSAEncryptor
from sealium.common.exceptions import CryptoError


class ClientKeyManager:
    """客户端密钥管理器（仅持有服务端公钥）。"""

    def __init__(self, server_public_key_pem: str | bytes) -> None:
        """
        :param server_public_key_pem: 服务端公钥 PEM 字符串或字节。
        """
        self._server_encryptor = RSAEncryptor.from_public_key_pem(server_public_key_pem)
        self._current_aes_key: Optional[bytes] = None  # 当前会话临时 AES 密钥

    def build_encrypted_request(self, request_plain: bytes) -> bytes:
        """
        构建双层加密请求包。

        :param request_plain: 请求明文（JSON 字节）。
        :return: 组装好的二进制数据包。
        """
        # 1. 生成临时 AES 密钥
        self._current_aes_key = AESEncryptor.generate_key()
        # 2. AES-GCM 加密业务明文
        nonce, ciphertext, tag = AESEncryptor.encrypt(self._current_aes_key, request_plain)
        # 3. RSA 加密 AES 密钥
        encrypted_aes_key = self._server_encryptor.encrypt(self._current_aes_key)
        # 4. 组装：encrypted_aes_key + nonce + ciphertext + tag
        return encrypted_aes_key + nonce + ciphertext + tag

    def decrypt_response(self, response_data: bytes) -> bytes:
        """
        解密 AES-GCM 响应包。

        :raises CryptoError: 尚未生成 AES 密钥或数据格式错误。
        """
        if self._current_aes_key is None:
            raise CryptoError("未生成 AES 密钥，请先调用 build_encrypted_request()")
        if len(response_data) < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
            raise CryptoError("响应数据过短，无法解析")

        nonce = response_data[:AES_GCM_NONCE_SIZE]
        tag = response_data[-AES_GCM_TAG_SIZE:]
        ciphertext = response_data[AES_GCM_NONCE_SIZE:-AES_GCM_TAG_SIZE]
        return AESEncryptor.decrypt(self._current_aes_key, nonce, ciphertext, tag)

    def clear_aes_key(self) -> None:
        """清除当前会话的 AES 密钥（内存清理）。"""
        self._current_aes_key = None
