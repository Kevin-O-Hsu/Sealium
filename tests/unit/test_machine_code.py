# tests/unit/test_machine_code.py
"""机器码生成单元测试。

测可注入的 generate_machine_code 与逐项哈希 hash_component；真实硬件采集
（WMI + 原生）仅在 Windows 真机有意义，做轻量冒烟。
"""

from __future__ import annotations

import os

import pytest

from sealium.common.exceptions import SealiumError
from sealium.common.fingerprint import MachineFingerprint, hash_component
from sealium.common.hardware.types import RawSurface
from sealium.common.machine_code import generate_machine_code


def _surfaces(seed: str = "x") -> list[RawSurface]:
    """构造稳定的测试表面（核心类齐全，spoof=0）。"""
    return [
        RawSurface("cpu", f"cpu-{seed}", "smbios"),
        RawSurface("board", f"board-{seed}", "smbios"),
        RawSurface("bios", f"bios-{seed}", "smbios"),
        RawSurface("system_uuid", f"uuid-{seed}", "smbios"),
        RawSurface("disk", f"disk-{seed}-0", "storage_ioctl", slot="0"),
        RawSurface("disk", f"disk-{seed}-1", "storage_ioctl", slot="1"),
    ]


class TestHashComponent:
    def test_deterministic(self):
        assert hash_component("cpu", "x") == hash_component("cpu", "x")

    def test_category_separated(self):
        # 不同类别同 raw → 不同哈希（类别入哈希防碰撞）
        assert hash_component("cpu", "x") != hash_component("board", "x")

    def test_different_raw_different_hash(self):
        assert hash_component("cpu", "x") != hash_component("cpu", "y")

    def test_returns_64_hex(self):
        h = hash_component("cpu", "x")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_pepper_injection_changes_hash(self):
        # 注入不同 pepper → 不同哈希（部署可定制；部署后不可变）
        assert hash_component("cpu", "x", pepper="a") != hash_component("cpu", "x", pepper="b")


class TestGenerateMachineCode:
    def test_returns_fingerprint_with_core_categories(self):
        fp = generate_machine_code(lambda: _surfaces())
        assert isinstance(fp, MachineFingerprint)
        cats = {c.category for c in fp.components}
        assert {"cpu", "board", "bios", "system_uuid"} <= cats
        assert fp.spoof_score == 0.0

    def test_deterministic(self):
        a = generate_machine_code(lambda: _surfaces())
        b = generate_machine_code(lambda: _surfaces())
        assert a == b

    def test_different_surfaces_yield_different_fingerprint(self):
        a = generate_machine_code(lambda: _surfaces("1"))
        b = generate_machine_code(lambda: _surfaces("2"))
        assert a != b

    def test_component_values_are_hashes(self):
        fp = generate_machine_code(lambda: _surfaces())
        for comp in fp.components:
            assert len(comp.value) == 64  # 逐项 sha256 hex
            assert all(c in "0123456789abcdef" for c in comp.value)

    def test_too_few_core_fails_safe(self):
        # 仅外围、无核心分量 → fail-safe 抛 SealiumError（不生成不可靠指纹）
        surfaces = [RawSurface("disk", "d", "wmi", slot="0")]
        with pytest.raises(SealiumError):
            generate_machine_code(lambda: surfaces)

    def test_too_few_core_with_fallback_secret(self):
        # 核心不足但有 fallback_secret_provider → 注入 system_uuid 核心分量，仍可生成
        surfaces = [RawSurface("disk", "d", "wmi", slot="0")]
        fp = generate_machine_code(
            lambda: surfaces, fallback_secret_provider=lambda: "install-secret"
        )
        assert isinstance(fp, MachineFingerprint)
        assert any(c.category == "system_uuid" and c.is_core for c in fp.components)


@pytest.mark.skipif(os.name != "nt", reason="采集仅 Windows 可用")
class TestWindowsCollection:
    def test_real_machine_generates_fingerprint(self):
        from sealium.common.hardware import collect_surfaces

        surfaces = collect_surfaces()
        assert isinstance(surfaces, list)
        fp = generate_machine_code()
        assert isinstance(fp, MachineFingerprint)


@pytest.mark.skipif(os.name == "nt", reason="非 Windows 才触发 RuntimeError")
class TestNonWindowsCollection:
    def test_default_collector_raises(self):
        with pytest.raises(RuntimeError):
            generate_machine_code()
