# tests/unit/hardware/test_native_surfaces.py
"""
原生表面采集的解析逻辑测试（SMBIOS 固件表 / 磁盘 IOCTL 结构解析）。

用固定字节 fixture 验证解析算法，不依赖真机；真机采集仅 Windows 冒烟。
"""

from __future__ import annotations

import os
import uuid

import pytest

from sealium.common.hardware.native_surfaces import (
    _iter_smbios_structures,
    _parse_smbios,
    _processor_id,
    _read_ansi,
    _string_at,
    _uuid_from,
    collect_native_surfaces,
)


# --------------------------------------------------------------------------- SMBIOS
def _bios_block() -> bytes:
    """Type0 (BIOS) 块：vendor=AMI, version=5.17。"""
    formatted = bytes([0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00])
    strings = b"AMI\x005.17\x00\x00"  # 两个串 + 终止 \x00
    return formatted + strings


def _processor_block(pid: bytes) -> bytes:
    """Type4 (Processor) 块：ProcessorID = pid（8 字节，offset 8）。"""
    formatted = bytes([0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + pid
    return formatted + b"\x00\x00"  # 空 string-set


def _end_block() -> bytes:
    """Type127 (end-of-table) 块。"""
    return bytes([0x7F, 0x04, 0x00, 0x00]) + b"\x00\x00"


class TestSmbiosParsing:
    def test_iter_structures(self):
        table = _bios_block() + _processor_block(b"\x11\x22\x33\x44\x55\x66\x77\x88") + _end_block()
        structs = list(_iter_smbios_structures(table))
        assert [s[0] for s in structs] == [0, 4, 127]

    def test_string_at_resolves_indices(self):
        formatted = bytes([0x00, 0x08, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00])
        strings = ["AMI", "5.17"]
        assert _string_at(formatted, strings, 4) == "AMI"
        assert _string_at(formatted, strings, 5) == "5.17"
        assert _string_at(formatted, strings, 6) is None  # 越界

    def test_uuid_from_valid(self):
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        formatted = bytes([0x01, 0x18, 0x00, 0x00]) + b"\x00" * 4 + u.bytes_le
        assert _uuid_from(formatted) == str(u)

    def test_uuid_from_all_zero_is_none(self):
        formatted = bytes([0x01, 0x18, 0x00, 0x00]) + b"\x00" * 20
        assert _uuid_from(formatted) is None

    def test_processor_id(self):
        pid = bytes([0x12, 0x0F, 0xA2, 0x00, 0xFF, 0xFB, 0x8B, 0x17])
        formatted = bytes([0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + pid
        # EAX=0x00A20F12、EDX=0x178BFBFF → EDX 在前（与 WMI ProcessorId 一致）
        assert _processor_id(formatted) == "178BFBFF00A20F12"

    def test_processor_id_all_zero_is_none(self):
        formatted = bytes([0x04, 0x10, 0x00, 0x00]) + b"\x00" * 12
        assert _processor_id(formatted) is None

    def test_parse_smbios_extracts_bios_and_cpu(self):
        pid = bytes([0x12, 0x0F, 0xA2, 0x00, 0xFF, 0xFB, 0x8B, 0x17])
        table = _bios_block() + _processor_block(pid) + _end_block()
        surfaces = _parse_smbios(table)
        by_cat = {s.category: s for s in surfaces}
        assert "AMI5.17" in by_cat["bios"].raw
        assert by_cat["bios"].source == "smbios"
        assert by_cat["cpu"].raw == "178BFBFF00A20F12"
        assert by_cat["cpu"].source == "smbios"


# --------------------------------------------------------------------------- IOCTL
class TestReadAnsi:
    def test_reads_until_null(self):
        buf = b"\x00\x00WD-WCAY\x00XXXX"
        assert _read_ansi(buf, 2) == "WD-WCAY"

    def test_zero_offset_is_none(self):
        assert _read_ansi(b"\x00WD\x00", 0) is None

    def test_out_of_range_is_none(self):
        assert _read_ansi(b"\x00\x00", 100) is None


# --------------------------------------------------------------------------- 平台守卫
@pytest.mark.skipif(os.name == "nt", reason="非 Windows 才触发 RuntimeError")
class TestNonWindows:
    def test_collect_native_raises_off_windows(self):
        with pytest.raises(RuntimeError):
            collect_native_surfaces()
