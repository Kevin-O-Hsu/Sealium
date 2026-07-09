# tests/unit/test_key_manager.py
"""客户端混合加密密钥管理单元测试。"""

from __future__ import annotations

import pytest

from sealium.client.key_manager import ClientKeyManager
from sealium.common.crypto import AESEncryptor, RSAEncryptor
from sealium.common.exceptions import CryptoError

KEY_SIZE = 2048


@pytest.fixture
def key_manager() -> ClientKeyManager:
    enc = RSAEncryptor.generate(key_size=KEY_SIZE)
    return ClientKeyManager(enc.export_public_key().decode())


class TestBuildEncryptedRequest:
    def test_packet_structure(self, key_manager: ClientKeyManager):
        plaintext = b'{"x": 1}'
        packet = key_manager.build_encrypted_request(plaintext)
        # [rsa(KEY_SIZE/8)] + [nonce(12)] + [ciphertext(len)] + [tag(16)]
        rsa_len = KEY_SIZE // 8
        assert len(packet) == rsa_len + 12 + len(plaintext) + 16

    def test_packet_is_not_plaintext(self, key_manager: ClientKeyManager):
        plaintext = b"sensitive request body"
        assert plaintext not in key_manager.build_encrypted_request(plaintext)


class TestDecryptResponse:
    def test_roundtrip(self, key_manager: ClientKeyManager):
        key_manager.build_encrypted_request(b"request")
        aes_key = key_manager._current_aes_key  # 同一会话密钥
        nonce, ciphertext, tag = AESEncryptor.encrypt(aes_key, b"server response")
        packet = nonce + ciphertext + tag
        assert key_manager.decrypt_response(packet) == b"server response"

    def test_decrypt_before_build_raises(self):
        enc = RSAEncryptor.generate(key_size=KEY_SIZE)
        km = ClientKeyManager(enc.export_public_key().decode())
        with pytest.raises(CryptoError):
            km.decrypt_response(b"\x00" * 40)

    def test_too_short_response_raises(self, key_manager: ClientKeyManager):
        key_manager.build_encrypted_request(b"request")
        with pytest.raises(CryptoError):
            key_manager.decrypt_response(b"\x00" * 5)  # < 12 + 16

    def test_corrupt_response_raises(self, key_manager: ClientKeyManager):
        key_manager.build_encrypted_request(b"request")
        with pytest.raises(Exception):
            key_manager.decrypt_response(b"\x01" * 100)


class TestMisc:
    def test_clear_aes_key(self, key_manager: ClientKeyManager):
        key_manager.build_encrypted_request(b"request")
        key_manager.clear_aes_key()
        with pytest.raises(CryptoError):
            key_manager.decrypt_response(b"\x00" * 40)

    def test_invalid_public_key_raises(self):
        with pytest.raises(Exception):
            ClientKeyManager("not a valid PEM")
