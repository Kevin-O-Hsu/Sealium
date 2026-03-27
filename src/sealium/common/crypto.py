# src/sealium/common/crypto.py
"""
RSA 加解密模块（OOP 设计）
支持 RSA4096 密钥生成、加密、解密，使用 OAEP 填充（SHA-256）
"""

from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class RSAEncryptor:
    """
    RSA 加解密器
    可持有公钥或私钥，用于加密/解密
    """

    def __init__(
        self,
        public_key: Optional[rsa.RSAPublicKey] = None,
        private_key: Optional[rsa.RSAPrivateKey] = None,
    ):
        """
        :param public_key: 可选，公钥对象
        :param private_key: 可选，私钥对象
        """
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def generate(cls, key_size: int = 4096) -> "RSAEncryptor":
        """
        生成新的 RSA 密钥对
        :param key_size: 密钥长度，默认 4096
        :return: RSAEncryptor 实例（同时包含公钥和私钥）
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return cls(public_key=public_key, private_key=private_key)

    @classmethod
    def from_public_key_pem(cls, pem_data: Union[bytes, str]) -> "RSAEncryptor":
        """
        从 PEM 格式公钥加载
        :param pem_data: PEM 格式公钥（bytes 或 str）
        :return: RSAEncryptor 实例（仅包含公钥）
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")
        public_key = serialization.load_pem_public_key(
            pem_data, backend=default_backend()
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("提供的 PEM 数据不是 RSA 公钥")
        return cls(public_key=public_key, private_key=None)

    @classmethod
    def from_private_key_pem(
        cls, pem_data: Union[bytes, str], password: Optional[bytes] = None
    ) -> "RSAEncryptor":
        """
        从 PEM 格式私钥加载
        :param pem_data: PEM 格式私钥（bytes 或 str）
        :param password: 私钥加密密码（可选）
        :return: RSAEncryptor 实例（仅包含私钥）
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")
        private_key = serialization.load_pem_private_key(
            pem_data, password=password, backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("提供的 PEM 数据不是 RSA 私钥")
        public_key = private_key.public_key()
        return cls(public_key=public_key, private_key=private_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        使用公钥加密数据
        :param plaintext: 明文（字节）
        :return: 密文（字节）
        :raises ValueError: 若未设置公钥或数据过长
        """
        if self._public_key is None:
            raise ValueError("未设置公钥，无法加密")

        # 检查数据长度：RSA-4096 OAEP 最多加密 4096/8 - 2*32 - 2 = 512 - 64 - 2 = 446 字节
        try:
            ciphertext = self._public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return ciphertext
        except ValueError as e:
            raise ValueError(f"加密失败，可能是数据过长：{e}")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        使用私钥解密数据
        :param ciphertext: 密文（字节）
        :return: 明文（字节）
        :raises ValueError: 若未设置私钥或解密失败
        """
        if self._private_key is None:
            raise ValueError("未设置私钥，无法解密")

        try:
            plaintext = self._private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return plaintext
        except Exception as e:
            raise ValueError(f"解密失败：{e}")

    def export_public_key(self, pem_format: bool = True) -> bytes:
        """
        导出公钥
        :param pem_format: True 返回 PEM 格式，False 返回 DER 格式
        :return: 公钥数据（字节）
        """
        if self._public_key is None:
            raise ValueError("未设置公钥，无法导出")
        if pem_format:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def export_private_key(
        self,
        pem_format: bool = True,
        encryption_algorithm: Optional[serialization.KeySerializationEncryption] = None,
    ) -> bytes:
        """
        导出私钥
        :param pem_format: True 返回 PEM 格式，False 返回 DER 格式
        :param encryption_algorithm: 加密算法（如 serialization.BestAvailableEncryption(password)）
        :return: 私钥数据（字节）
        """
        if self._private_key is None:
            raise ValueError("未设置私钥，无法导出")
        if encryption_algorithm is None:
            encryption_algorithm = serialization.NoEncryption()
        if pem_format:
            return self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )
        else:
            return self._private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

    @property
    def has_public_key(self) -> bool:
        """是否持有公钥"""
        return self._public_key is not None

    @property
    def has_private_key(self) -> bool:
        """是否持有私钥"""
        return self._private_key is not None

    @property
    def key_size(self) -> int:
        """密钥长度（位）"""
        if self._public_key:
            return self._public_key.key_size
        elif self._private_key:
            return self._private_key.key_size
        else:
            raise ValueError("未加载任何密钥")

    @property
    def max_plaintext_size(self) -> int:
        """
        最大可加密明文长度（字节）
        计算公式：key_size//8 - 2*hash_len - 2
        SHA256 摘要长度 32
        """
        if self._public_key is None:
            raise ValueError("未设置公钥，无法计算")
        key_bytes = self._public_key.key_size // 8
        hash_len = hashes.SHA256.digest_size  # 32
        return key_bytes - 2 * hash_len - 2
