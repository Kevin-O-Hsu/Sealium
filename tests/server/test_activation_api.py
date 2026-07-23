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

    def test_oversized_body_returns_413(self, client):
        """MEDIUM-001: 超过 64KB 上限的请求体直接 413，防内存耗尽 DoS。"""
        from sealium.common.constants import MAX_ACTIVATION_BODY_BYTES

        big = b"x" * (MAX_ACTIVATION_BODY_BYTES + 1)
        resp = client.post("/v1/activation", content=big)
        assert resp.status_code == 413
        assert resp.content == b""


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
        # LOW-008：对外固定通用消息，不回显内部异常细节（字段名/类型校验等）
        assert data["error_msg"] == "请求格式错误"
        assert "缺少" not in data["error_msg"]
        assert "KeyError" not in data["error_msg"]

    def test_invalid_field_type_no_internal_leak(
        self, client, server_public_pem, fixed_timestamp, make_fingerprint
    ):
        """LOW-008：类型校验异常的细节（如「timestamp 必须为整数」）不得回显进响应。"""
        request_dict = {
            "activation_code": "c",
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": "not-an-int",  # 类型非法，from_dict 抛 ValueError
            "nonce": "n",
        }
        packet, km = build_packet(server_public_pem, request_dict)
        resp = client.post("/v1/activation", content=packet)
        data = decrypt(km, resp.content)
        assert data["result"] == "error"
        assert data["error_msg"] == "请求格式错误"
        # 内部校验细节不外泄
        assert "整数" not in data["error_msg"]
        assert "timestamp" not in data["error_msg"]

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
