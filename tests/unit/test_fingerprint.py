# tests/unit/test_fingerprint.py
"""指纹核心抽象与匹配算法单元测试（纯算法层）。"""

from __future__ import annotations

import json

import pytest

from sealium.common.fingerprint import (
    Component,
    MachineFingerprint,
    MachineIdPolicy,
    matches,
    to_storage,
)


def _full_fp(seed: str = "m", *, spoof: float = 0.0, drift: bool = False) -> MachineFingerprint:
    """全类别指纹：seed 决定核心 value；drift 让外围（disk/mac）不同。"""
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


class TestMatches:
    def test_identical_fingerprints_match(self):
        assert matches(_full_fp("m"), _full_fp("m"), MachineIdPolicy.default()) is True

    def test_all_core_different_rejected(self):
        assert matches(_full_fp("m"), _full_fp("other"), MachineIdPolicy.default()) is False

    def test_peripheral_drift_tolerated(self):
        """核心相同、外围（磁盘/MAC）更换 → 仍判同机（阈值容错）。"""
        policy = MachineIdPolicy.default()
        assert matches(_full_fp("m"), _full_fp("m", drift=True), policy) is True

    def test_core_min_is_independent_gate(self):
        """threshold=0 让加权门槛失效，单独验证 core_min 门槛。"""
        policy = MachineIdPolicy(threshold=0.0, core_min=3, spoof_max=0.5)
        bound = MachineFingerprint(
            components=(
                Component("cpu", "x", True),
                Component("board", "x", True),
                Component("bios", "B", True),
                Component("system_uuid", "U", True),
            )
        )
        # 仅 cpu+board 匹配（2 core < 3）→ False
        incoming2 = MachineFingerprint(
            components=(
                Component("cpu", "x", True),
                Component("board", "x", True),
                Component("bios", "DIFF", True),
                Component("system_uuid", "DIFF", True),
            )
        )
        assert matches(bound, incoming2, policy) is False
        # cpu+board+bios 匹配（3 core ≥ 3）→ True
        incoming3 = MachineFingerprint(
            components=(
                Component("cpu", "x", True),
                Component("board", "x", True),
                Component("bios", "B", True),
                Component("system_uuid", "DIFF", True),
            )
        )
        assert matches(bound, incoming3, policy) is True

    def test_spoof_score_rejected(self):
        """spoof_score 超 spoof_max → 直接 False（即使指纹全匹配）。"""
        policy = MachineIdPolicy.default()  # spoof_max=0.5
        assert matches(_full_fp("m"), _full_fp("m", spoof=0.6), policy) is False


class TestSerialization:
    def test_to_dict_from_dict_roundtrip(self):
        fp = _full_fp("m", spoof=0.2)
        assert MachineFingerprint.from_dict(fp.to_dict()) == fp

    def test_canonical_is_stable_and_json(self):
        fp = _full_fp("m")
        c = fp.canonical()
        assert c == fp.canonical()  # 稳定
        json.loads(c)  # 合法 JSON

    def test_to_storage_equals_canonical(self):
        fp = _full_fp("m")
        assert to_storage(fp) == fp.canonical()

    def test_from_dict_rejects_non_dict(self):
        with pytest.raises(ValueError):
            MachineFingerprint.from_dict("not-a-dict")  # type: ignore[arg-type]

    def test_from_dict_rejects_unsupported_version(self):
        with pytest.raises(ValueError):
            MachineFingerprint.from_dict({"v": 99, "components": [], "spoof": 0})

    def test_from_dict_rejects_empty_components(self):
        with pytest.raises(ValueError):
            MachineFingerprint.from_dict({"v": 1, "components": [], "spoof": 0})

    def test_from_dict_rejects_spoof_out_of_range(self):
        with pytest.raises(ValueError):
            MachineFingerprint.from_dict(
                {"v": 1, "components": [{"c": "cpu", "h": "x", "core": True}], "spoof": 2.0}
            )

    def test_from_dict_rejects_bad_component(self):
        with pytest.raises(ValueError):
            MachineFingerprint.from_dict(
                {"v": 1, "components": [{"c": "cpu", "h": "", "core": True}], "spoof": 0}
            )
