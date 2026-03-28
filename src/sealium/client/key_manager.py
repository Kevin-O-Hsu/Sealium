# src/sealium/client/key_manager.py
"""
客户端密钥管理模块
负责：加载服务端公钥、生成临时客户端密钥对、加密请求/解密响应
"""

from typing import Optional

from sealium.common.crypto import RSAEncryptor


class ClientKeyManager:
    """
    客户端密钥管理器

    使用流程：
    1. 初始化时传入服务端公钥 PEM 字符串
    2. 调用 generate_temp_keypair() 生成临时密钥对，获取公钥用于请求
    3. 使用 encrypt_request() 加密请求数据
    4. 收到响应后，使用 decrypt_response() 解密
    """

    def __init__(self, server_public_key_pem: str):
        """
        初始化密钥管理器

        :param server_public_key_pem: 服务端公钥 PEM 字符串
        """
        # 保存服务端公钥字符串（可用于调试或重新加载）
        self._server_public_key_pem = server_public_key_pem
        # 创建服务端加密器（仅公钥，用于加密请求）
        self._server_encryptor = RSAEncryptor.from_public_key_pem(server_public_key_pem)

        # 临时客户端密钥对（每次请求前生成）
        self._temp_client_encryptor: Optional[RSAEncryptor] = None

    def generate_temp_keypair(self) -> str:
        """
        生成临时客户端密钥对（RSA4096）

        :return: 客户端公钥 PEM 字符串（用于发送给服务端）
        """
        # 生成新的 RSA 密钥对（默认 4096 位）
        self._temp_client_encryptor = RSAEncryptor.generate(4096)
        # 导出公钥为 PEM 字符串
        pub_pem_bytes = self._temp_client_encryptor.export_public_key(pem_format=True)
        return pub_pem_bytes.decode('utf-8')

    def encrypt_request(self, plaintext: bytes) -> bytes:
        """
        使用服务端公钥加密请求数据

        :param plaintext: 明文数据（字节）
        :return: 密文（字节）
        """
        return self._server_encryptor.encrypt(plaintext)

    def decrypt_response(self, ciphertext: bytes) -> bytes:
        """
        使用临时客户端私钥解密响应数据

        :param ciphertext: 密文（字节）
        :return: 明文（字节）
        :raises ValueError: 如果尚未生成临时密钥对
        """
        if self._temp_client_encryptor is None:
            raise ValueError("尚未生成临时密钥对，请先调用 generate_temp_keypair()")
        return self._temp_client_encryptor.decrypt(ciphertext)

    @property
    def has_temp_keypair(self) -> bool:
        """是否已生成临时密钥对"""
        return self._temp_client_encryptor is not None