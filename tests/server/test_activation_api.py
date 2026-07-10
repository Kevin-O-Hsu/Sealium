# tests/server/test_activation_api.py
"""激活接口 HTTP 层测试（FastAPI TestClient，进程内）。

直接构造加密请求包打到接口，校验状态码、Content-Type 与加密响应。
"""

from __future__ import annotations

import json

import pytest

from sealium.client.key_manager import ClientKeyManager
from sealium.common.constants import AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, RSA_KEY_SIZE


def build_packet(server_public_pem: str, request_dict: dict):
    """用客户端密钥管理器构建加密请求包，返回 (packet, key_manager)。"""
    km = ClientKeyManager(server_public_pem)
    packet = km.build_encrypted_request(json.dumps(request_dict).encode())
    return packet, km


def decrypt(km: ClientKeyManager, content: bytes) -> dict:
    return json.loads(km.decrypt_response(content).decode())


class TestHealthAndErrors:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "service": "activation"}

    def test_empty_body_returns_400(self, client):
        resp = client.post("/v1/activation", content=b"")
        assert resp.status_code == 400
        assert resp.content == b""

    def test_corrupt_packet_returns_400(self, client):
        resp = client.post("/v1/activation", content=b"\x01" * 100)
        assert resp.status_code == 400

    def test_rsa_decrypt_failure_returns_400(self, client):
        # 包结构完整但 RSA 段为随机字节，解密 AES 密钥失败
        rsa_len = RSA_KEY_SIZE // 8
        packet = (
            b"\x00" * rsa_len
            + b"\x00" * AES_GCM_NONCE_SIZE
            + b"x"
            + b"\x00" * AES_GCM_TAG_SIZE
        )
        resp = client.post("/v1/activation", content=packet)
        assert resp.status_code == 400


class TestActivationRoundtrip:
    def test_successful_activation(
        self, client, server_public_pem, storage, unused_code, fixed_timestamp, make_fingerprint
    ):
        request_dict = {
            "activation_code": unused_code,
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": fixed_timestamp,
            "nonce": "n1",
        }
        packet, km = build_packet(server_public_pem, request_dict)
        resp = client.post("/v1/activation", content=packet)

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"
        data = decrypt(km, resp.content)
        assert data["result"] == "success"
        assert data["nonce"] == "n1"
        assert data["features"] == ["pro"]
        assert data["authorized_until"] == "2026-12-31"

    def test_missing_code_returns_encrypted_error(
        self, client, server_public_pem, fixed_timestamp, make_fingerprint
    ):
        request_dict = {
            "activation_code": "ghost",
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": fixed_timestamp,
            "nonce": "n",
        }
        packet, km = build_packet(server_public_pem, request_dict)
        resp = client.post("/v1/activation", content=packet)
        assert resp.status_code == 200
        data = decrypt(km, resp.content)
        assert data["result"] == "error"
        # 统一为通用提示（GRAY-001）
        assert "已被使用" in data["error_msg"]

    def test_invalid_request_format_returns_encrypted_error(
        self, client, server_public_pem
    ):
        # 缺字段：from_dict 会抛 KeyError
        packet, km = build_packet(server_public_pem, {"activation_code": "c"})
        resp = client.post("/v1/activation", content=packet)
        data = decrypt(km, resp.content)
        assert data["result"] == "error"

    def test_response_is_not_plain_json(
        self, client, server_public_pem, unused_code, fixed_timestamp, make_fingerprint
    ):
        request_dict = {
            "activation_code": unused_code,
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": fixed_timestamp,
            "nonce": "n",
        }
        packet, _ = build_packet(server_public_pem, request_dict)
        resp = client.post("/v1/activation", content=packet)
        # 加密响应是随机二进制，按字节内容抛 JSONDecodeError 或 UnicodeDecodeError
        with pytest.raises((json.JSONDecodeError, UnicodeDecodeError)):
            json.loads(resp.content)
