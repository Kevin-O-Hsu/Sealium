# tests/unit/test_crypto_transport.py
"""加密传输层（请求包解析 / 响应加密）单元测试。"""

from __future__ import annotations

import json

import pytest

from sealium.common.crypto import AESEncryptor, RSAEncryptor
from sealium.server.crypto_transport import (
    decrypt_request,
    encrypt_response,
    parse_encrypted_request,
)

KEY_SIZE = 2048


@pytest.fixture
def encryptor() -> RSAEncryptor:
    return RSAEncryptor.generate(key_size=KEY_SIZE)


class TestParseEncryptedRequest:
    def test_parses_fields_correctly(self, encryptor: RSAEncryptor):
        aes_key = AESEncryptor.generate_key()
        nonce, ciphertext, tag = AESEncryptor.encrypt(aes_key, b"payload")
        encrypted_aes_key = encryptor.encrypt(aes_key)
        packet = encrypted_aes_key + nonce + ciphertext + tag

        parts = parse_encrypted_request(packet, rsa_key_size=KEY_SIZE)
        assert parts == (encrypted_aes_key, nonce, ciphertext, tag)

    def test_too_short_packet_raises(self):
        with pytest.raises(ValueError):
            parse_encrypted_request(b"\x00" * 10, rsa_key_size=KEY_SIZE)

    def test_missing_tag_raises(self, encryptor: RSAEncryptor):
        aes_key = AESEncryptor.generate_key()
        encrypted_aes_key = encryptor.encrypt(aes_key)
        # enc_aes + nonce(12) 后不足以包含 tag
        packet = encrypted_aes_key + b"\x00" * 12
        with pytest.raises(ValueError):
            parse_encrypted_request(packet, rsa_key_size=KEY_SIZE)


class TestDecryptRequest:
    def test_recovers_key_and_payload(self, encryptor: RSAEncryptor):
        aes_key = AESEncryptor.generate_key()
        payload = json.dumps({"activation_code": "c"}).encode()
        nonce, ciphertext, tag = AESEncryptor.encrypt(aes_key, payload)
        encrypted_aes_key = encryptor.encrypt(aes_key)

        recovered_key, request_dict = decrypt_request(
            encryptor, encrypted_aes_key, nonce, ciphertext, tag
        )
        assert recovered_key == aes_key
        assert request_dict == {"activation_code": "c"}


class TestEncryptResponse:
    def test_roundtrip(self):
        aes_key = AESEncryptor.generate_key()
        data = {"result": "success", "authorized_until": "2026-12-31"}

        packet = encrypt_response(data, aes_key)
        nonce = packet[:12]
        tag = packet[-16:]
        ciphertext = packet[12:-16]

        decrypted = AESEncryptor.decrypt(aes_key, nonce, ciphertext, tag)
        assert json.loads(decrypted.decode()) == data
