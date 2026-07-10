# tests/client/test_activator.py
"""客户端 Activator 单元/集成测试（TestClient 桥接，无需真实服务端）。"""

from __future__ import annotations

import json

import pytest

from sealium.client.activator import Activator, ActivationError
from sealium.common.models import ActivationStatus


def test_activate_success(client, make_activator, storage, unused_code, make_fingerprint):
    activator = make_activator(client)
    resp = activator.activate(unused_code)
    assert resp.result == "success"
    assert resp.features == ["pro"]
    assert resp.authorized_until == "2026-12-31"
    assert resp.nonce  # 回显 nonce

    stored = storage.get_by_code(unused_code)
    assert stored.status == ActivationStatus.USED
    assert stored.bound_machine_code == make_fingerprint()


def test_nonce_mismatch_raises(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)
    bad_response = json.dumps(
        {"result": "success", "authorized_until": "2026-12-31", "features": [], "nonce": "WRONG"}
    ).encode()
    monkeypatch.setattr(activator.key_manager, "decrypt_response", lambda data: bad_response)
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "nonce" in str(exc.value).lower()


def test_timestamp_provider_failure(server_public_pem, make_fingerprint):
    def no_time():
        raise RuntimeError("no time")

    # 注入固定机器码，使本测试只聚焦"时间戳提供者失败"路径，与平台无关
    # （否则默认 WMI 采集在非 Windows 上会先抛错，掩盖被测路径）。
    activator = Activator(
        "http://localhost/v1/activation",
        server_public_pem,
        timestamp_provider=no_time,
        machine_code_provider=lambda: make_fingerprint(),
    )
    with pytest.raises(ActivationError) as exc:
        activator.activate("any")
    assert "时间戳" in str(exc.value)


def test_machine_code_provider_failure(server_public_pem):
    """机器码提供者抛异常时，activate() 应收敛为 ActivationError（契约一致性）。"""

    def no_machine():
        raise RuntimeError("no hardware")

    activator = Activator(
        "http://localhost/v1/activation",
        server_public_pem,
        timestamp_provider=lambda: 1700000000,
        machine_code_provider=no_machine,
    )
    with pytest.raises(ActivationError) as exc:
        activator.activate("any")
    assert "机器码" in str(exc.value)


def test_encrypt_request_failure(client, make_activator, unused_code, monkeypatch):
    activator = make_activator(client)

    def boom(data):
        raise ValueError("encrypt failed")

    monkeypatch.setattr(activator.key_manager, "build_encrypted_request", boom)
    with pytest.raises(ActivationError) as exc:
        activator.activate(unused_code)
    assert "加密请求" in str(exc.value)


def test_network_failure(server_public_pem, make_fingerprint):
    activator = Activator(
        "http://127.0.0.1:9/v1/activation",
        server_public_pem,
        timestamp_provider=lambda: 1700000000,
        machine_code_provider=lambda: make_fingerprint(),
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
