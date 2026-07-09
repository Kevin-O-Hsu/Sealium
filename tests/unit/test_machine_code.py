# tests/unit/test_machine_code.py
"""机器码生成单元测试。

重点测试纯函数 hash_hardware_info 与可注入的 generate_machine_code；
WMI 采集（collect_hardware_info）仅在 Windows 真机有意义，做轻量冒烟。
"""

from __future__ import annotations

import os

import pytest

from sealium.common.machine_code import (
    generate_machine_code,
    hash_hardware_info,
)


class TestHashHardwareInfo:
    def test_deterministic(self):
        info = [("cpu", "ID1"), ("board", "B1"), ("mac", "AA")]
        assert hash_hardware_info(info) == hash_hardware_info(info)

    def test_returns_64_hex(self):
        code = hash_hardware_info([("cpu", "x"), ("board", "y"), ("mac", "z")])
        assert len(code) == 64
        assert all(c in "0123456789abcdef" for c in code)

    def test_order_independent_via_sort(self):
        """带类型标签并按标签排序，交换顺序不影响结果（防位置交换攻击）。"""
        a = [("cpu", "1"), ("board", "2"), ("mac", "3")]
        b = [("mac", "3"), ("board", "2"), ("cpu", "1")]
        assert hash_hardware_info(a) == hash_hardware_info(b)

    def test_different_values_yield_different_hash(self):
        a = [("cpu", "1"), ("board", "2"), ("mac", "3")]
        b = [("cpu", "1"), ("board", "2"), ("mac", "9")]
        assert hash_hardware_info(a) != hash_hardware_info(b)

    def test_fallback_when_too_few_items(self):
        # 少于 3 条会补充 fallback（时间）并仍生成合法码
        code = hash_hardware_info([("cpu", "x")])
        assert len(code) == 64


class TestGenerateMachineCode:
    def test_with_injected_collector_matches_hash(self):
        fixed = [("cpu", "C"), ("board", "B"), ("mac", "M")]
        code = generate_machine_code(lambda: fixed)
        assert len(code) == 64
        assert code == hash_hardware_info(fixed)

    def test_injected_collector_isolation(self):
        # 不同的注入数据产生不同的机器码
        a = generate_machine_code(lambda: [("cpu", "A"), ("board", "B"), ("mac", "C")])
        b = generate_machine_code(lambda: [("cpu", "Z"), ("board", "B"), ("mac", "C")])
        assert a != b


@pytest.mark.skipif(os.name != "nt", reason="WMI 采集仅 Windows 可用")
class TestWindowsWmiCollection:
    def test_collect_returns_tuples(self):
        from sealium.common.machine_code import collect_hardware_info

        info = collect_hardware_info()
        assert isinstance(info, list)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in info)

    def test_default_collector_real_machine(self):
        code = generate_machine_code()
        assert len(code) == 64
        assert all(c in "0123456789abcdef" for c in code)


@pytest.mark.skipif(os.name == "nt", reason="非 Windows 才触发 RuntimeError")
class TestNonWindowsCollection:
    def test_default_collector_raises(self):
        with pytest.raises(RuntimeError):
            generate_machine_code()
