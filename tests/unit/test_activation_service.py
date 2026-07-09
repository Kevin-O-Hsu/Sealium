# tests/unit/test_activation_service.py
"""激活业务核心单元测试：覆盖全部业务分支与错误码。"""

from __future__ import annotations

from datetime import datetime

import pytest

from sealium.common.models import ActivationCode, ActivationRequest, ActivationStatus
from sealium.server.activation_service import ActivationService
from sealium.server.replay_guard import ReplayGuard

NOW = datetime(2026, 1, 1, 12, 0, 0)
NOW_TS = int(NOW.timestamp())


def make_request(code="c", machine="m", timestamp=NOW_TS, nonce="n") -> ActivationRequest:
    return ActivationRequest(
        activation_code=code, machine_code=machine, timestamp=timestamp, nonce=nonce
    )


@pytest.fixture
def service(storage) -> ActivationService:
    return ActivationService(storage, ReplayGuard(), 300, now_provider=lambda: NOW)


class TestFormatValidation:
    def test_empty_code(self, service: ActivationService):
        resp = service.process(make_request(code=""))
        assert resp.result == "error"
        assert "格式无效" in resp.error_msg

    def test_non_string_code(self, service: ActivationService):
        req = ActivationRequest(
            activation_code=123, machine_code="m", timestamp=NOW_TS, nonce="n"
        )
        resp = service.process(req)
        assert resp.result == "error"
        assert "格式无效" in resp.error_msg


class TestTimestampValidation:
    def test_past_timestamp_rejected(self, service: ActivationService):
        resp = service.process(make_request(timestamp=NOW_TS - 99999))
        assert resp.result == "error"
        assert "时间戳" in resp.error_msg

    def test_future_timestamp_rejected(self, service: ActivationService):
        resp = service.process(make_request(timestamp=NOW_TS + 99999))
        assert resp.result == "error"
        assert "时间戳" in resp.error_msg

    def test_boundary_within_tolerance_ok(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))
        resp = service.process(make_request(timestamp=NOW_TS - 300))  # 边界值
        assert resp.result == "success"


class TestReplayProtection:
    def test_same_nonce_rejected(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))
        first = service.process(make_request(nonce="same"))
        assert first.result == "success"
        second = service.process(make_request(nonce="same"))
        assert second.result == "error"
        assert "重复" in second.error_msg


class TestCodeLookup:
    def test_missing_code(self, service: ActivationService):
        resp = service.process(make_request(code="ghost"))
        assert resp.result == "error"
        assert "不存在" in resp.error_msg


class TestUsedCodeBranches:
    def test_same_machine_idempotent(self, service: ActivationService, storage):
        storage.create(
            ActivationCode(
                activation_code="c",
                bound_machine_code="m",
                status=ActivationStatus.USED,
                features=["pro"],
                expires_at=datetime(2026, 12, 31),
            )
        )
        resp = service.process(make_request(machine="m"))
        assert resp.result == "success"
        assert resp.authorized_until == "2026-12-31"
        assert resp.features == ["pro"]
        assert resp.nonce == "n"

    def test_different_machine_rejected(self, service: ActivationService, storage):
        storage.create(
            ActivationCode(
                activation_code="c",
                bound_machine_code="m",
                status=ActivationStatus.USED,
            )
        )
        resp = service.process(make_request(machine="other"))
        assert resp.result == "error"
        assert "其他设备" in resp.error_msg


class TestExpiry:
    def test_expired_unused_code(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c", expires_at=datetime(2020, 1, 1)))
        resp = service.process(make_request())
        assert resp.result == "error"
        assert "过期" in resp.error_msg


class TestFreshActivation:
    def test_success_binds_machine_and_echoes_nonce(
        self, service: ActivationService, storage
    ):
        storage.create(
            ActivationCode(
                activation_code="c",
                features=["pro"],
                expires_at=datetime(2026, 12, 31),
            )
        )
        resp = service.process(make_request(machine="mymc", nonce="client-nonce"))
        assert resp.result == "success"
        assert resp.authorized_until == "2026-12-31"
        assert resp.features == ["pro"]
        assert resp.nonce == "client-nonce"

        stored = storage.get_by_code("c")
        assert stored.status == ActivationStatus.USED
        assert stored.bound_machine_code == "mymc"
        assert stored.activated_at is not None

    def test_permanent_authorization(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))  # 无 expires_at = 永久
        resp = service.process(make_request())
        assert resp.result == "success"
        assert resp.authorized_until == "永久"

    def test_db_error_returns_error(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))

        def boom(*args, **kwargs):
            raise RuntimeError("db down")

        storage.bind_machine_code = boom
        resp = service.process(make_request())
        assert resp.result == "error"
        assert "数据库更新失败" in resp.error_msg
