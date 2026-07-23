# tests/unit/test_activation_service.py
"""激活业务核心单元测试：覆盖全部业务分支与错误码。"""

from __future__ import annotations

import threading
from datetime import datetime

import pytest

from sealium.common.fingerprint import Component, MachineFingerprint
from sealium.common.models import ActivationCode, ActivationRequest, ActivationStatus
from sealium.server.activation_service import ActivationService
from sealium.server.replay_guard import ReplayGuard

NOW = datetime(2026, 1, 1, 12, 0, 0)
NOW_TS = int(NOW.timestamp())


def _fp(seed: str = "m", *, spoof: float = 0.0, drift: bool = False) -> MachineFingerprint:
    """构造测试指纹：相同 seed → 核心分量相同；drift=True → 外围分量不同。"""
    core = f"core-{seed}"
    periph = f"periph-drift-{seed}" if drift else f"periph-{seed}"
    return MachineFingerprint(
        components=(
            Component("cpu", core, True),
            Component("board", core, True),
            Component("bios", core, True),
            Component("system_uuid", core, True),
            Component("disk", periph, False),
            Component("mac", periph, False),
        ),
        spoof_score=spoof,
    )


def make_request(code="c", machine: MachineFingerprint | None = None, timestamp=NOW_TS, nonce="n") -> ActivationRequest:
    return ActivationRequest(
        activation_code=code, machine_code=machine or _fp(), timestamp=timestamp, nonce=nonce
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
            activation_code=123, machine_code=_fp(), timestamp=NOW_TS, nonce="n"
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
        # 与“已被他机占用”对外不可区分（GRAY-001 关闭存在性枚举）
        assert "已被使用" in resp.error_msg


class TestUsedCodeBranches:
    def test_same_machine_idempotent(self, service: ActivationService, storage):
        storage.create(
            ActivationCode(
                activation_code="c",
                bound_machine_code=_fp("m"),
                status=ActivationStatus.USED,
                features=["pro"],
                expires_at=datetime(2026, 12, 31),
            )
        )
        resp = service.process(make_request(machine=_fp("m")))
        assert resp.result == "success"
        assert resp.authorized_until == "2026-12-31"
        assert resp.features == ["pro"]
        assert resp.nonce == "n"

    def test_different_machine_rejected(self, service: ActivationService, storage):
        storage.create(
            ActivationCode(
                activation_code="c",
                bound_machine_code=_fp("m"),
                status=ActivationStatus.USED,
            )
        )
        resp = service.process(make_request(machine=_fp("other")))
        assert resp.result == "error"
        # 与“码不存在”对外不可区分（GRAY-001）
        assert "已被使用" in resp.error_msg


class TestExpiry:
    def test_expired_unused_code(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c", expires_at=datetime(2020, 1, 1)))
        resp = service.process(make_request())
        assert resp.result == "error"
        # LOW-001：对外与「不存在/他机占用」合并为统一提示，关闭存在性枚举；
        # 「过期」细节只进审计日志，不出现在对外响应里。
        assert "已被使用" in resp.error_msg
        assert "过期" not in resp.error_msg


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
        resp = service.process(make_request(machine=_fp("mymc"), nonce="client-nonce"))
        assert resp.result == "success"
        assert resp.authorized_until == "2026-12-31"
        assert resp.features == ["pro"]
        assert resp.nonce == "client-nonce"

        stored = storage.get_by_code("c")
        assert stored.status == ActivationStatus.USED
        assert stored.bound_machine_code == _fp("mymc")
        assert stored.activated_at is not None

    def test_permanent_authorization(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))  # 无 expires_at = 永久
        resp = service.process(make_request())
        assert resp.result == "success"
        assert resp.authorized_until == "永久"

    def test_db_error_returns_generic_error(self, service: ActivationService, storage):
        storage.create(ActivationCode(activation_code="c"))

        def boom(*args, **kwargs):
            raise RuntimeError("db down")

        storage.bind_machine_code = boom
        resp = service.process(make_request())
        assert resp.result == "error"
        # 对外通用提示，不回显原始异常（LOW-003）
        assert "激活失败" in resp.error_msg
        assert "db down" not in resp.error_msg


class TestConcurrentBindingAtomicity:
    """回归测试：并发抢绑同一未用码，仅一台机器能成功（HIGH-001）。"""

    def test_one_code_activates_exactly_one_machine_under_concurrency(
        self, storage: ActivationCodeStorage
    ):
        # 用足够大的防重放缓存，确保各线程独立 nonce 不被误逐
        svc = ActivationService(
            storage, ReplayGuard(max_size=100000), 300, now_provider=lambda: NOW
        )
        storage.create(ActivationCode(activation_code="shared", features=["pro"]))

        n = 25
        results: list = []
        barrier = threading.Barrier(n)

        def worker(i: int):
            req = ActivationRequest(
                activation_code="shared",
                machine_code=_fp(f"machine{i}"),
                timestamp=NOW_TS,
                nonce=f"nonce{i}",
            )
            barrier.wait()  # 同时释放所有线程，最大化竞态窗口
            results.append(svc.process(req).result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = results.count("success")
        assert successes == 1, f"期望仅 1 台成功，实际 {successes} 台（竞态未修复）"
        # 其余均被拒为“不可用”；赢家绑定的指纹必为其中之一
        bound = storage.get_by_code("shared")
        assert bound.status == ActivationStatus.USED
        possible = {_fp(f"machine{i}") for i in range(n)}
        assert bound.bound_machine_code in possible


class TestReplayCacheFlushResistance:
    """MEDIUM-006: 不存在的码不进 replay 缓存，杜绝用随机码灌满 LRU 的冲刷攻击。"""

    def test_nonexistent_codes_do_not_pollute_replay_cache(self, storage):
        guard = ReplayGuard()
        svc = ActivationService(storage, guard, 300, now_provider=lambda: NOW)
        baseline = len(guard._store._seen)
        for i in range(50):
            resp = svc.process(make_request(code=f"ghost-{i}", nonce=f"n-{i}"))
            assert resp.result == "error"
            assert "已被使用" in resp.error_msg
        # 不存在的码不进缓存：缓存大小不应增长
        assert len(guard._store._seen) == baseline

    def test_existing_code_still_enters_replay_cache(self, storage):
        """MEDIUM-006 回归：存在的码仍进缓存，合法重放被拦截。"""
        guard = ReplayGuard()
        svc = ActivationService(storage, guard, 300, now_provider=lambda: NOW)
        storage.create(ActivationCode(activation_code="real"))
        first = svc.process(make_request(code="real", nonce="once"))
        assert first.result == "success"
        assert len(guard._store._seen) == 1  # 存在的码进了缓存
        second = svc.process(make_request(code="real", nonce="once"))
        assert second.result == "error"
        assert "重复" in second.error_msg
