# src/sealium/common/crypto.py
"""
RSA + AES 加解密模块（OOP 设计）
支持 RSA4096 密钥生成、加密、解密，使用 OAEP 填充（SHA-256）
支持 AES-256-GCM 加解密
"""

from typing import Optional, Union, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

from sealium.common.constants import (
    RSA_KEY_SIZE,
    AES_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
)


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
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def generate(cls, key_size: int = RSA_KEY_SIZE) -> "RSAEncryptor":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return cls(public_key=public_key, private_key=private_key)

    @classmethod
    def from_public_key_pem(cls, pem_data: Union[bytes, str]) -> "RSAEncryptor":
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
        if self._public_key is None:
            raise ValueError("未设置公钥，无法加密")
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
        return self._public_key is not None

    @property
    def has_private_key(self) -> bool:
        return self._private_key is not None

    @property
    def key_size(self) -> int:
        if self._public_key:
            return self._public_key.key_size
        elif self._private_key:
            return self._private_key.key_size
        else:
            raise ValueError("未加载任何密钥")

    @property
    def max_plaintext_size(self) -> int:
        if self._public_key is None:
            raise ValueError("未设置公钥，无法计算")
        key_bytes = self._public_key.key_size // 8
        hash_len = hashes.SHA256.digest_size  # 32
        return key_bytes - 2 * hash_len - 2


class AESEncryptor:
    """
    AES-256-GCM 加解密器
    """

    @staticmethod
    def generate_key() -> bytes:
        """生成随机 AES-256 密钥（32 字节）"""
        return secrets.token_bytes(AES_KEY_SIZE // 8)

    @staticmethod
    def encrypt(
        key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        使用 AES-256-GCM 加密
        :param key: 32 字节密钥
        :param plaintext: 明文
        :param associated_data: 附加认证数据（可选）
        :return: (nonce, ciphertext, tag)
        """
        if len(key) != AES_KEY_SIZE // 8:
            raise ValueError(f"密钥长度必须为 {AES_KEY_SIZE // 8} 字节")
        nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        # ciphertext 最后 16 字节是 tag，前 len(ciphertext)-16 是密文
        tag = ciphertext[-AES_GCM_TAG_SIZE:]
        ciphertext_without_tag = ciphertext[:-AES_GCM_TAG_SIZE]
        return nonce, ciphertext_without_tag, tag

    @staticmethod
    def decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        解密 AES-256-GCM 密文
        :param key: 32 字节密钥
        :param nonce: 12 字节 nonce
        :param ciphertext: 密文（不含 tag）
        :param tag: 16 字节认证标签
        :param associated_data: 附加认证数据
        :return: 明文
        """
        if len(key) != AES_KEY_SIZE // 8:
            raise ValueError(f"密钥长度必须为 {AES_KEY_SIZE // 8} 字节")
        if len(nonce) != AES_GCM_NONCE_SIZE:
            raise ValueError(f"nonce 长度必须为 {AES_GCM_NONCE_SIZE} 字节")
        if len(tag) != AES_GCM_TAG_SIZE:
            raise ValueError(f"tag 长度必须为 {AES_GCM_TAG_SIZE} 字节")
        aesgcm = AESGCM(key)
        full_ciphertext = ciphertext + tag
        plaintext = aesgcm.decrypt(nonce, full_ciphertext, associated_data)
        return plaintext
