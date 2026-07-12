# src/sealium/common/crypto.py
"""
加密原语：RSA-4096-OAEP(SHA-256) 与 AES-256-GCM。

本模块只提供无状态、无 I/O 的加解密能力。混合加密的数据包组装/拆解
（RSA 加密 AES 密钥 + AES 加密业务数据）见
``sealium.server.crypto_transport`` 与 ``sealium.client.key_manager``。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sealium.common.constants import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    AES_KEY_SIZE,
    RSA_KEY_SIZE,
)
from sealium.common.exceptions import CryptoError


class RSAEncryptor:
    """RSA 加解密器，可仅持公钥或同时持公钥与私钥。"""

    def __init__(
        self,
        public_key: Optional[rsa.RSAPublicKey] = None,
        private_key: Optional[rsa.RSAPrivateKey] = None,
    ) -> None:
        self._public_key = public_key
        self._private_key = private_key

    @classmethod
    def generate(cls, key_size: int = RSA_KEY_SIZE) -> RSAEncryptor:
        """生成新的 RSA 密钥对（默认 4096 位）。"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return cls(public_key=private_key.public_key(), private_key=private_key)

    @classmethod
    def from_public_key_pem(cls, pem_data: Union[bytes, str]) -> RSAEncryptor:
        """从 PEM 数据加载公钥。"""
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")
        public_key = serialization.load_pem_public_key(pem_data)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoError("提供的 PEM 数据不是 RSA 公钥")
        return cls(public_key=public_key, private_key=None)

    @classmethod
    def from_private_key_pem(
        cls, pem_data: Union[bytes, str], password: Optional[bytes] = None
    ) -> RSAEncryptor:
        """从 PEM 数据加载私钥（可选口令加密）。"""
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")
        private_key = serialization.load_pem_private_key(pem_data, password=password)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoError("提供的 PEM 数据不是 RSA 私钥")
        return cls(public_key=private_key.public_key(), private_key=private_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """使用公钥 + OAEP(SHA-256) 加密。"""
        if self._public_key is None:
            raise CryptoError("未设置公钥，无法加密")
        try:
            return self._public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as exc:
            raise CryptoError(f"加密失败，可能是数据过长：{exc}") from exc

    def decrypt(self, ciphertext: bytes) -> bytes:
        """使用私钥 + OAEP(SHA-256) 解密。"""
        if self._private_key is None:
            raise CryptoError("未设置私钥，无法解密")
        try:
            return self._private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise CryptoError(f"解密失败：{exc}") from exc

    def export_public_key(self, pem_format: bool = True) -> bytes:
        """导出公钥（PEM 或 DER）。"""
        if self._public_key is None:
            raise CryptoError("未设置公钥，无法导出")
        encoding = serialization.Encoding.PEM if pem_format else serialization.Encoding.DER
        return self._public_key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_key(
        self,
        pem_format: bool = True,
        encryption_algorithm: Optional[serialization.KeySerializationEncryption] = None,
    ) -> bytes:
        """导出私钥（PEM 或 DER，可选加密）。"""
        if self._private_key is None:
            raise CryptoError("未设置私钥，无法导出")
        if encryption_algorithm is None:
            encryption_algorithm = serialization.NoEncryption()
        encoding = serialization.Encoding.PEM if pem_format else serialization.Encoding.DER
        return self._private_key.private_bytes(
            encoding=encoding,
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
        if self._private_key:
            return self._private_key.key_size
        raise CryptoError("未加载任何密钥")

    @property
    def max_plaintext_size(self) -> int:
        """OAEP(SHA-256) 下单次加密的最大明文字节数。"""
        if self._public_key is None:
            raise CryptoError("未设置公钥，无法计算")
        key_bytes = self._public_key.key_size // 8
        hash_len = hashes.SHA256.digest_size  # 32
        return key_bytes - 2 * hash_len - 2


class AESEncryptor:
    """AES-256-GCM 加解密器。"""

    @staticmethod
    def generate_key() -> bytes:
        """生成随机 AES-256 密钥（32 字节）。"""
        return secrets.token_bytes(AES_KEY_SIZE // 8)

    @staticmethod
    def encrypt(
        key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None
    ) -> tuple[bytes, bytes, bytes]:
        """
        AES-256-GCM 加密。

        :return: ``(nonce, ciphertext, tag)``，其中 ciphertext 不含 tag。
        """
        if len(key) != AES_KEY_SIZE // 8:
            raise CryptoError(f"密钥长度必须为 {AES_KEY_SIZE // 8} 字节")
        nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        tag = ciphertext_and_tag[-AES_GCM_TAG_SIZE:]
        ciphertext = ciphertext_and_tag[:-AES_GCM_TAG_SIZE]
        return nonce, ciphertext, tag

    @staticmethod
    def decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """AES-256-GCM 解密。"""
        if len(key) != AES_KEY_SIZE // 8:
            raise CryptoError(f"密钥长度必须为 {AES_KEY_SIZE // 8} 字节")
        if len(nonce) != AES_GCM_NONCE_SIZE:
            raise CryptoError(f"nonce 长度必须为 {AES_GCM_NONCE_SIZE} 字节")
        if len(tag) != AES_GCM_TAG_SIZE:
            raise CryptoError(f"tag 长度必须为 {AES_GCM_TAG_SIZE} 字节")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)


def hash_activation_code(code: str, pepper: str) -> str:
    """激活码索引哈希：HMAC-SHA256(code, pepper)（MEDIUM-002）。

    激活码本身为 128 位高熵随机串，验证时只需相等比较，故适合哈希存储——
    DB 文件泄露时无法直接读出可用码，把"读取"降级回"预像不可行"。
    HMAC 提供域分隔（per-deployment pepper），查询性能不变（仍走主键索引）。

    :param code: 明文激活码（仅生成时颁发一次，绝不入库）。
    :param pepper: 部署私有盐；未配置时用 :data:`CODE_HASH_PEPPER_DEFAULT`。
    :return: 64 位十六进制摘要，作为 DB 主键 ``code_hash``。
    """
    return hmac.new(
        pepper.encode("utf-8"), code.encode("utf-8"), hashlib.sha256
    ).hexdigest()
