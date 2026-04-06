# src/sealium/client/key_manager.py
"""
客户端密钥管理模块（无私钥版本）
负责：加载服务端公钥、生成临时 AES 密钥、构建双层加密请求、解密 AES 响应
"""

from typing import Optional
from sealium.common.crypto import RSAEncryptor, AESEncryptor
from sealium.common.constants import RSA_KEY_SIZE, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE


class ClientKeyManager:
    """
    客户端密钥管理器（无私钥，仅持有服务端公钥）

    使用流程：
    1. 初始化时加载服务端公钥
    2. 每次请求调用 build_encrypted_request() 生成临时 AES 密钥并加密请求
    3. 收到响应后调用 decrypt_response() 使用相同的 AES 密钥解密
    """

    def __init__(self, server_public_key_pem: str):
        """
        初始化密钥管理器

        :param server_public_key_pem: 服务端公钥 PEM 字符串
        """
        self._server_encryptor = RSAEncryptor.from_public_key_pem(server_public_key_pem)
        self._current_aes_key: Optional[bytes] = None  # 当前会话的 AES 密钥

    def build_encrypted_request(self, request_plain: bytes) -> bytes:
        """
        构建双层加密请求：
        1. 生成临时 AES-256 密钥
        2. 用 AES-GCM 加密请求明文，得到 (nonce, ciphertext, tag)
        3. 用服务器 RSA 公钥加密 AES 密钥
        4. 组装二进制包：RSA_encrypted_aes_key (固定长度) + nonce + ciphertext + tag

        :param request_plain: 请求明文（JSON 字节）
        :return: 加密后的请求数据包
        """
        # 1. 生成临时 AES 密钥
        self._current_aes_key = AESEncryptor.generate_key()

        # 2. AES 加密请求明文
        nonce, ciphertext, tag = AESEncryptor.encrypt(
            self._current_aes_key, request_plain
        )

        # 3. RSA 加密 AES 密钥
        encrypted_aes_key = self._server_encryptor.encrypt(self._current_aes_key)

        # 4. 组装数据包
        # 格式: [encrypted_aes_key (512 bytes)] + [nonce (12 bytes)] + [ciphertext (变长)] + [tag (16 bytes)]
        result = encrypted_aes_key + nonce + ciphertext + tag
        return result

    def decrypt_response(self, response_data: bytes) -> bytes:
        """
        解密 AES 加密的响应数据
        响应包格式: [nonce (12 bytes)] + [ciphertext (变长)] + [tag (16 bytes)]

        :param response_data: 服务器返回的二进制数据
        :return: 解密后的明文（JSON 字节）
        :raises ValueError: 如果尚未生成 AES 密钥或数据格式错误
        """
        if self._current_aes_key is None:
            raise ValueError("未生成 AES 密钥，请先调用 build_encrypted_request()")

        # 解析响应包
        if len(response_data) < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
            raise ValueError("响应数据过短，无法解析")

        nonce = response_data[:AES_GCM_NONCE_SIZE]
        tag = response_data[-AES_GCM_TAG_SIZE:]
        ciphertext = response_data[AES_GCM_NONCE_SIZE:-AES_GCM_TAG_SIZE]

        # 解密
        plaintext = AESEncryptor.decrypt(self._current_aes_key, nonce, ciphertext, tag)
        return plaintext

    def clear_aes_key(self):
        """清除当前会话的 AES 密钥（可选，用于内存清理）"""
        self._current_aes_key = None
