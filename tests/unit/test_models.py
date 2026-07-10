# tests/unit/test_models.py
"""共享数据模型单元测试。"""

from __future__ import annotations

from datetime import datetime

import pytest

from sealium.common.fingerprint import Component, MachineFingerprint
from sealium.common.models import (
    ActivationCode,
    ActivationRequest,
    ActivationResponse,
    ActivationStatus,
)


def _fp(seed: str = "m") -> MachineFingerprint:
    """构造测试指纹（仅用于本文件 roundtrip，值用可读字符串）。"""
    return MachineFingerprint(
        components=(
            Component("cpu", f"c-{seed}", True),
            Component("board", f"b-{seed}", True),
        ),
        spoof_score=0.0,
    )


class TestActivationStatus:
    def test_values(self):
        assert ActivationStatus.UNUSED == 0
        assert ActivationStatus.USED == 1


class TestActivationCode:
    def test_defaults(self):
        code = ActivationCode(activation_code="abc")
        assert code.bound_machine_code is None
        assert code.activated_at is None
        assert code.expires_at is None
        assert code.features == []
        assert code.status == ActivationStatus.UNUSED
        assert not code.is_used()

    def test_is_used(self):
        assert ActivationCode(activation_code="x", status=ActivationStatus.USED).is_used()

    def test_is_expired_with_injected_now(self):
        expired = ActivationCode(activation_code="x", expires_at=datetime(2020, 1, 1))
        valid = ActivationCode(activation_code="x", expires_at=datetime(2030, 1, 1))
        assert expired.is_expired(now=datetime(2025, 1, 1)) is True
        assert valid.is_expired(now=datetime(2025, 1, 1)) is False

    def test_is_expired_none_expires_at(self):
        assert ActivationCode(activation_code="x").is_expired() is False

    def test_to_from_dict_roundtrip(self):
        fp = _fp("mc")
        original = ActivationCode(
            activation_code="code1",
            bound_machine_code=fp,
            activated_at=datetime(2026, 1, 1, 12, 0, 0),
            expires_at=datetime(2026, 12, 31),
            features=["a", "b"],
            status=ActivationStatus.USED,
        )
        data = original.to_dict()
        assert data["status"] == 1
        assert data["features"] == ["a", "b"]
        assert data["bound_machine_code"] == fp.to_dict()
        restored = ActivationCode.from_dict(data)
        assert restored.activation_code == "code1"
        assert restored.bound_machine_code == fp
        assert restored.features == ["a", "b"]
        assert restored.status == ActivationStatus.USED
        assert restored.activated_at == datetime(2026, 1, 1, 12, 0, 0)


class TestActivationRequest:
    def test_to_dict(self):
        fp = _fp("m")
        req = ActivationRequest(
            activation_code="c", machine_code=fp, timestamp=123, nonce="n"
        )
        assert req.to_dict() == {
            "activation_code": "c",
            "machine_code": fp.to_dict(),
            "timestamp": 123,
            "nonce": "n",
        }

    def test_from_dict_roundtrip(self):
        fp = _fp("m")
        req = ActivationRequest.from_dict(
            {"activation_code": "c", "machine_code": fp.to_dict(), "timestamp": 7, "nonce": "n"}
        )
        assert req.timestamp == 7
        assert req.nonce == "n"
        assert req.machine_code == fp

    def test_from_dict_rejects_non_dict_machine_code(self):
        with pytest.raises(ValueError):
            ActivationRequest.from_dict(
                {"activation_code": "c", "machine_code": "not-a-fingerprint", "timestamp": 7, "nonce": "n"}
            )

    def test_from_dict_rejects_missing_machine_code(self):
        with pytest.raises(ValueError):
            ActivationRequest.from_dict(
                {"activation_code": "c", "timestamp": 7, "nonce": "n"}
            )


class TestActivationResponse:
    def test_success_factory(self):
        resp = ActivationResponse.success("2026-12-31", ["pro"], "nonce123")
        assert resp.result == "success"
        assert resp.authorized_until == "2026-12-31"
        assert resp.features == ["pro"]
        assert resp.nonce == "nonce123"
        assert resp.error_msg is None

    def test_error_factory(self):
        resp = ActivationResponse.error("bad", nonce="n")
        assert resp.result == "error"
        assert resp.error_msg == "bad"
        assert resp.nonce == "n"

    def test_to_dict_omits_none_fields(self):
        data = ActivationResponse.success("d", ["f"], "n").to_dict()
        assert "error_msg" not in data
        assert data == {"result": "success", "authorized_until": "d", "features": ["f"], "nonce": "n"}

    def test_from_dict(self):
        resp = ActivationResponse.from_dict({"result": "error", "error_msg": "x"})
        assert resp.result == "error"
        assert resp.error_msg == "x"
