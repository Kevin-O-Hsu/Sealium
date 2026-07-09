# src/sealium/common/machine_code.py
"""
机器码生成：组合 Windows 硬件标识符并取 SHA-256。

设计要点
--------
* 采集（WMI）与哈希解耦：``hash_hardware_info`` 是纯函数，可独立单测；
  ``collect_hardware_info`` 仅在 Windows 可用，且惰性导入 ``wmi``。
* ``generate_machine_code`` 接受可注入的 ``collector``，测试时可传入
  固定的硬件信息列表，无需真实硬件 / WMI。
* 不在模块顶层做任何 I/O 或打印，导入本模块零副作用。
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from collections.abc import Callable, Iterable

# 一条硬件信息：(类型标签, 值)
HardwareInfo = tuple[str, str]
# 硬件采集器：返回硬件信息列表
HardwareCollector = Callable[[], list[HardwareInfo]]

# 物理硬盘允许的接口类型（过滤虚拟光驱 / USB）
_DISK_INTERFACE_TYPES = ("IDE", "SCSI", "SATA", "NVMe", "RAID")
# 虚拟 / 无效 MAC 前缀
_INVALID_MAC_PREFIXES = ("000000000000", "FFFFFFFFFFFF")


def collect_hardware_info() -> list[HardwareInfo]:
    """
    通过 WMI 采集硬件标识符（仅 Windows）。

    组合 CPU、主板、BIOS、操作系统、物理硬盘、网卡 MAC、机箱、显示器、
    计算机名等多类信息，并做去噪过滤。``wmi`` 在调用时惰性导入。
    """
    if os.name != "nt":
        raise RuntimeError("机器码 WMI 采集仅支持 Windows 平台")

    import wmi  # 惰性导入，避免在非 Windows / 测试环境顶层失败

    c = wmi.WMI()
    info: list[HardwareInfo] = []

    # 1. CPU 信息（权重高）
    try:
        for processor in c.Win32_Processor():
            cpu_id = getattr(processor, "ProcessorId", None)
            if cpu_id:
                info.append(("cpu", cpu_id.strip()))
                break
    except Exception:
        pass

    # 2. 主板信息（权重高）
    try:
        for board in c.Win32_BaseBoard():
            serial = getattr(board, "SerialNumber", None)
            product = getattr(board, "Product", None)
            if serial or product:
                info.append(("board", f"{serial or ''}{product or ''}".strip()))
                break
    except Exception:
        pass

    # 3. BIOS 信息（权重高）
    try:
        for bios in c.Win32_BIOS():
            serial = getattr(bios, "SerialNumber", None)
            version = getattr(bios, "Version", None)
            if serial or version:
                info.append(("bios", f"{serial or ''}{version or ''}".strip()))
                break
    except Exception:
        pass

    # 4. 操作系统信息（权重中）
    try:
        for system in c.Win32_OperatingSystem():
            serial = getattr(system, "SerialNumber", None)
            if serial:
                info.append(("os", serial.strip()))
                break
    except Exception:
        pass

    # 5. 物理硬盘信息（权重高）—— 最多取 3 块
    try:
        disk_count = 0
        for disk in c.Win32_DiskDrive():
            if disk_count >= 3:
                break
            interface = getattr(disk, "InterfaceType", "")
            if interface in _DISK_INTERFACE_TYPES:
                serial = getattr(disk, "SerialNumber", None)
                model = getattr(disk, "Model", None)
                if serial or model:
                    info.append(("disk", f"{serial or ''}{model or ''}".strip()))
                    disk_count += 1
    except Exception:
        pass

    # 6. MAC 地址（权重中）—— 收集有效网卡，排序后取前 3 个保证一致性
    try:
        mac_addresses: list[str] = []
        for nic in c.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress:
                mac = nic.MACAddress.replace(":", "").replace("-", "").upper()
                if mac and not any(
                    mac.startswith(prefix) for prefix in _INVALID_MAC_PREFIXES
                ):
                    mac_addresses.append(mac)
        mac_addresses.sort()
        for mac in mac_addresses[:3]:
            info.append(("mac", mac))
    except Exception:
        pass

    # 7. 机箱序列号（权重中）
    try:
        for chassis in c.Win32_SystemEnclosure():
            serial = getattr(chassis, "SerialNumber", None)
            if serial:
                info.append(("chassis", serial.strip()))
                break
    except Exception:
        pass

    # 8. 显示器信息（权重低）
    try:
        for monitor in c.Win32_DesktopMonitor():
            name = getattr(monitor, "Name", None)
            pnpid = getattr(monitor, "PNPDeviceID", None)
            if name or pnpid:
                info.append(("monitor", f"{name or ''}{pnpid or ''}".strip()))
                break
    except Exception:
        pass

    # 9. 计算机名和用户名（权重低）
    try:
        for computer in c.Win32_ComputerSystem():
            name = getattr(computer, "Name", None)
            username = getattr(computer, "UserName", None)
            if name or username:
                info.append(("computer", f"{name or ''}{username or ''}".strip()))
                break
    except Exception:
        pass

    return info


def hash_hardware_info(hardware_info: Iterable[HardwareInfo]) -> str:
    """
    将硬件信息列表哈希为 64 位十六进制机器码（纯函数）。

    * 带类型标签并按标签排序后拼接，防止位置交换攻击。
    * 信息过少（<3 条）时补充当前时间，保证可用性（降低安全性）。
    * 熵值过低（唯一字符 <10）时加盐重新哈希，避免简单重复。
    """
    info_list = list(hardware_info)
    if len(info_list) < 3:
        info_list.append(("fallback", str(time.time())))

    combined_parts = [f"{tag}:{value}" for tag, value in sorted(info_list, key=lambda x: x[0])]
    combined = "|".join(combined_parts).encode("utf-8")

    machine_code = hashlib.sha256(combined).hexdigest()

    if len(set(machine_code)) < 10:  # 熵值过低
        salt = secrets.token_hex(16)
        machine_code = hashlib.sha256(combined + salt.encode("utf-8")).hexdigest()

    return machine_code


def generate_machine_code(collector: HardwareCollector | None = None) -> str:
    """
    生成机器码。

    :param collector: 硬件采集器；为 ``None`` 时使用默认 WMI 采集器。
                     测试时可注入返回固定硬件信息的采集器。
    :return: 64 位十六进制机器码字符串。
    """
    collect = collector if collector is not None else collect_hardware_info
    return hash_hardware_info(collect())
