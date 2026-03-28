# src/sealium/client/key_manager.py
"""
客户端密钥管理模块
负责：加载固定客户端密钥对、加载服务端公钥、加密请求/解密响应
"""

import os

from sealium.common.crypto import RSAEncryptor


class ClientKeyManager:
        """
    客户端密钥管理器（固定密钥对版本）

    使用流程：
    1. 初始化时加载服务端公钥和客户端密钥对（从文件或硬编码）
    2. 使用 encrypt_request() 加密请求数据
    3. 使用 decrypt_response() 解密响应数据
    """

        def __init__(self, server_public_key_pem: str, client_private_key_pem: str):
                """
        初始化密钥管理器

        :param server_public_key_pem: 服务端公钥 PEM 字符串
        :param client_private_key_pem: 客户端私钥 PEM 字符串
        """
                # 创建服务端加密器（仅公钥，用于加密请求）
                self._server_encryptor = RSAEncryptor.from_public_key_pem(server_public_key_pem)
                # 创建客户端解密器（包含私钥，用于解密响应）
                self._client_decryptor = RSAEncryptor.from_private_key_pem(client_private_key_pem)

                # 导出客户端公钥（供服务端使用）
                self._client_public_key_pem = self._client_decryptor.export_public_key().decode('utf-8')

        def encrypt_request(self, plaintext: bytes) -> bytes:
                """
        使用服务端公钥加密请求数据

        :param plaintext: 明文数据（字节）
        :return: 密文（字节）
        """
                return self._server_encryptor.encrypt(plaintext)

        def decrypt_response(self, ciphertext: bytes) -> bytes:
                """
        使用客户端私钥解密响应数据

        :param ciphertext: 密文（字节）
        :return: 明文（字节）
        """
                return self._client_decryptor.decrypt(ciphertext)

        def get_client_public_key(self) -> str:
                """
        获取客户端公钥 PEM 字符串（供服务端使用）

        :return: 客户端公钥 PEM 字符串
        """
                return self._client_public_key_pem


def load_client_keys_from_files(client_private_path: str) -> str:
        """
    从文件加载客户端私钥

    :param client_private_path: 客户端私钥文件路径
    :return: 客户端私钥 PEM 字符串
    """
        if not os.path.exists(client_private_path):
                raise FileNotFoundError(f"客户端私钥文件不存在: {client_private_path}")
        with open(client_private_path, "r") as f:
                return f.read()