# tests/client/test_activator.py
"""客户端 Activator 单元/集成测试（TestClient 桥接，无需真实服务端）。"""

from __future__ import annotations

import json

import pytest

from sealium.client.activator import Activator, ActivationError
from sealium.common.models import ActivationStatus


def test_activate_success(client, make_activator, storage, unused_code):
    activator = make_activator(client)
    resp = activator.activate(unused_code)
    assert resp.result == "success"
    assert resp.features == ["pro"]
    assert resp.authorized_until == "2026-12-31"
    assert resp.nonce  # 回显 nonce

    stored = storage.get_by_code(unused_code)
    assert stored.status == ActivationStatus.USED
    assert stored.bound_machine_code == "deadbeef" * 8


def test_nonce_mismatch_raises(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)
    bad_response = json.dumps(
        {"result": "success", "authorized_until": "2026-12-31", "features": [], "nonce": "WRONG"}
    ).encode()
    monkeypatch.setattr(activator.key_manager, "decrypt_response", lambda data: bad_response)
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "nonce" in str(exc.value).lower()


def test_timestamp_provider_failure(server_public_pem):
    def no_time():
        raise RuntimeError("no time")

    activator = Activator(
        "http://localhost/v1/activation", server_public_pem, timestamp_provider=no_time
    )
    with pytest.raises(ActivationError) as exc:
        activator.activate("any")
    assert "时间戳" in str(exc.value)


def test_encrypt_request_failure(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)

    def boom(data):
        raise ValueError("encrypt failed")

    monkeypatch.setattr(activator.key_manager, "build_encrypted_request", boom)
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "加密请求" in str(exc.value)


def test_network_failure(server_public_pem):
    activator = Activator(
        "http://127.0.0.1:9/v1/activation",
        server_public_pem,
        timestamp_provider=lambda: 1700000000,
        machine_code_provider=lambda: "m",
    )
    with pytest.raises(ActivationError) as exc:
        activator.activate("any")
    assert "网络请求" in str(exc.value)


def test_decrypt_response_failure(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)

    def boom(data):
        raise Exception("decrypt failed")

    monkeypatch.setattr(activator.key_manager, "decrypt_response", boom)
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "解密响应" in str(exc.value)


def test_parse_response_failure(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)
    monkeypatch.setattr(activator.key_manager, "decrypt_response", lambda data: b"not json{{{")
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "解析响应" in str(exc.value)


def test_invalid_public_key_raises():
    with pytest.raises(Exception):
        Activator("http://localhost/v1/activation", "not a valid pem")
