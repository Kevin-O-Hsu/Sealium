# tests/unit/test_crypto.py
"""加密原语单元测试：RSA-4096-OAEP / AES-256-GCM。"""

from __future__ import annotations

import pytest

from sealium.common.crypto import AESEncryptor, RSAEncryptor
from sealium.common.exceptions import CryptoError

# 单元测试用 2048 位加速（加解密逻辑与位数无关）；协议默认 4096 在 e2e 测试覆盖
KEY_SIZE = 2048


class TestRSAEncryptor:
    def test_generate_keypair(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        assert enc.has_public_key
        assert enc.has_private_key
        assert enc.key_size == KEY_SIZE

    def test_encrypt_decrypt_roundtrip(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        ciphertext = enc.encrypt(b"hello sealium")
        assert ciphertext != b"hello sealium"
        assert enc.decrypt(ciphertext) == b"hello sealium"

    def test_load_public_key_only(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        only_pub = RSAEncryptor.from_public_key_pem(enc.export_public_key())
        assert only_pub.has_public_key
        assert not only_pub.has_private_key

    def test_load_private_key_derives_public(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        loaded = RSAEncryptor.from_private_key_pem(enc.export_private_key())
        assert loaded.has_private_key
        assert loaded.has_public_key

    def test_pem_accepts_str_and_bytes(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        pem = enc.export_public_key()
        from_bytes = RSAEncryptor.from_public_key_pem(pem)
        from_str = RSAEncryptor.from_public_key_pem(pem.decode())
        assert enc.decrypt(from_bytes.encrypt(b"x")) == b"x"
        assert enc.decrypt(from_str.encrypt(b"y")) == b"y"

    def test_cross_keypair_roundtrip(self):
        sender = RSAEncryptor.generate(key_size=KEY_SIZE)
        receiver = RSAEncryptor.generate(key_size=KEY_SIZE)
        receiver_pub = RSAEncryptor.from_public_key_pem(receiver.export_public_key())
        ciphertext = receiver_pub.encrypt(b"for receiver")
        assert receiver.decrypt(ciphertext) == b"for receiver"
        # 发送方的私钥无法解密发给接收方的密文
        with pytest.raises(CryptoError):
            sender.decrypt(ciphertext)

    def test_encrypt_without_public_key_raises(self):
        with pytest.raises(CryptoError):
            RSAEncryptor().encrypt(b"data")

    def test_decrypt_without_private_key_raises(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        only_pub = RSAEncryptor.from_public_key_pem(enc.export_public_key())
        with pytest.raises(CryptoError):
            only_pub.decrypt(b"\x00" * (KEY_SIZE // 8))

    def test_decrypt_corrupt_ciphertext_raises(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        with pytest.raises(CryptoError):
            enc.decrypt(b"not valid ciphertext at all")

    def test_max_plaintext_size(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        assert enc.max_plaintext_size == KEY_SIZE // 8 - 2 * 32 - 2

    def test_export_der_format(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        assert not enc.export_public_key(pem_format=False).startswith(b"-----")


class TestAESEncryptor:
    def test_generate_key_length(self):
        assert len(AESEncryptor.generate_key()) == 32

    def test_encrypt_decrypt_roundtrip(self):
        key = AESEncryptor.generate_key()
        nonce, ciphertext, tag = AESEncryptor.encrypt(key, b"secret payload")
        assert len(nonce) == 12
        assert len(tag) == 16
        assert AESEncryptor.decrypt(key, nonce, ciphertext, tag) == b"secret payload"

    def test_associated_data_roundtrip(self):
        key = AESEncryptor.generate_key()
        nonce, ciphertext, tag = AESEncryptor.encrypt(key, b"data", b"header")
        assert AESEncryptor.decrypt(key, nonce, ciphertext, tag, b"header") == b"data"

    def test_associated_data_mismatch_fails(self):
        key = AESEncryptor.generate_key()
        nonce, ciphertext, tag = AESEncryptor.encrypt(key, b"data", b"header")
        with pytest.raises(Exception):
            AESEncryptor.decrypt(key, nonce, ciphertext, tag, b"other")

    def test_tamper_detection(self):
        key = AESEncryptor.generate_key()
        nonce, ciphertext, tag = AESEncryptor.encrypt(key, b"data")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(Exception):
            AESEncryptor.decrypt(key, nonce, tampered, tag)

    def test_wrong_key_length_raises(self):
        with pytest.raises(CryptoError):
            AESEncryptor.encrypt(b"short", b"data")

    def test_wrong_nonce_length_raises(self):
        key = AESEncryptor.generate_key()
        with pytest.raises(CryptoError):
            AESEncryptor.decrypt(key, b"short", b"c", b"\x00" * 16)

    def test_wrong_tag_length_raises(self):
        key = AESEncryptor.generate_key()
        with pytest.raises(CryptoError):
            AESEncryptor.decrypt(key, b"\x00" * 12, b"c", b"short")
