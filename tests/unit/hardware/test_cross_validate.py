# tests/unit/hardware/test_cross_validate.py
"""交叉验证 / 占位符清洗 / spoof 计分单元测试（纯逻辑）。"""

from __future__ import annotations

from sealium.common.hardware.cross_validate import (
    is_placeholder,
    normalize,
    scrub_and_score,
)
from sealium.common.hardware.types import RawSurface


class TestNormalize:
    def test_strips_and_uppercases(self):
        assert normalize("  Wd-Wcay  ") == "WD-WCAY"

    def test_drops_all_whitespace(self):
        # 某些存储驱动返回的序列号每字符间插空格 —— 抹平后才能与 WMI 源比对
        assert normalize("W D - W C") == "WD-WC"

    def test_none_to_empty(self):
        assert normalize(None) == ""


class TestPlaceholder:
    def test_common_placeholders(self):
        assert is_placeholder("To be filled by O.E.M.")
        assert is_placeholder("Default String")
        assert is_placeholder("None")
        assert is_placeholder("Not Specified")

    def test_all_zero_or_all_f(self):
        assert is_placeholder("000000000000")
        assert is_placeholder("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
        assert is_placeholder("00:00:00:00:00:00")

    def test_real_value_not_placeholder(self):
        assert not is_placeholder("WD-WCAY00528367")
        assert not is_placeholder("178BFBFF00A20F12")


class TestScrubAndScore:
    def test_consistent_sources_no_spoof(self):
        """同盘多源序列号一致 → 单分量、spoof=0。"""
        surfaces = [
            RawSurface("disk", "WD-ABC", "storage_ioctl", slot="0"),
            RawSurface("disk", "WD-ABC", "wmi", slot="0"),
        ]
        clean, spoof = scrub_and_score(surfaces)
        assert spoof == 0.0
        assert len([c for c in clean if c.category == "disk"]) == 1

    def test_inconsistent_sources_flagged(self):
        """同盘多源序列号不一致 → spoof 计分。"""
        surfaces = [
            RawSurface("disk", "WD-ABC", "storage_ioctl", slot="0"),
            RawSurface("disk", "WD-XYZ", "wmi", slot="0"),
        ]
        _, spoof = scrub_and_score(surfaces)
        assert spoof >= 0.25

    def test_placeholder_core_dropped_and_spoofed(self):
        """核心类占位符 → 该分量被剔除 + spoof 计分。"""
        surfaces = [RawSurface("board", "To be filled by O.E.M.", "wmi")]
        clean, spoof = scrub_and_score(surfaces)
        assert spoof >= 0.1
        assert all(c.category != "board" for c in clean)

    def test_placeholder_peripheral_dropped_no_spoof(self):
        """外围类占位符 → 剔除但不计 spoof（仅核心类占位才计）。"""
        surfaces = [RawSurface("disk", "Default String", "wmi", slot="0")]
        clean, spoof = scrub_and_score(surfaces)
        assert spoof == 0.0
        assert all(c.category != "disk" for c in clean)

    def test_native_source_preferred_as_representative(self):
        """多源同值时，原生 surface（smbios）优先作为代表。"""
        surfaces = [
            RawSurface("cpu", "CPUID", "wmi"),
            RawSurface("cpu", "CPUID", "smbios"),
        ]
        clean, _ = scrub_and_score(surfaces)
        cpu = [c for c in clean if c.category == "cpu"][0]
        assert cpu.source == "smbios"

    def test_multi_value_peripherals_kept_separate(self):
        """多块盘 / 多张网卡各占独立分量（不因 slot 不同被合并）。"""
        surfaces = [
            RawSurface("disk", "D0", "storage_ioctl", slot="0"),
            RawSurface("disk", "D1", "storage_ioctl", slot="1"),
        ]
        clean, spoof = scrub_and_score(surfaces)
        disks = [c for c in clean if c.category == "disk"]
        assert len(disks) == 2
        assert spoof == 0.0

    def test_spoof_capped_at_one(self):
        """大量不一致 → spoof 不超过 1.0。"""
        surfaces = [
            RawSurface("disk", f"D{i}-a", "storage_ioctl", slot=str(i))
            for i in range(10)
        ] + [
            RawSurface("disk", f"D{i}-b", "wmi", slot=str(i))
            for i in range(10)
        ]
        _, spoof = scrub_and_score(surfaces)
        assert spoof == 1.0
