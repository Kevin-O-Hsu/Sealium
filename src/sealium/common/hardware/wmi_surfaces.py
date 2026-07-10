# src/sealium/common/hardware/wmi_surfaces.py
"""
WMI 多表面采集（作为原生表面的交叉源 + 部分类别的主源）。

采集 cpu / board / bios / system_uuid / memory / disk / mac / chassis / tpm，
每个值以 :class:`RawSurface` 形式产出（带 ``source="wmi"`` 与 ``slot``）。多值类
（disk/memory/mac）的每个物理设备用独立 ``slot``，避免交叉验证时被误合并。
每个查询独立 ``try/except`` **fail-soft**——任一来源失败只跳过该来源。

注意：WMI 层相对上层，spoof 工具可 hook 其 provider 改返回值；故原生表面
（:mod:`sealium.common.hardware.native_surfaces`）优先，WMI 作为交叉验证源。
"""

from __future__ import annotations

import os
import re

from sealium.common.hardware.cross_validate import is_placeholder, normalize
from sealium.common.hardware.types import RawSurface

# 物理硬盘允许的接口类型（过滤虚拟光驱 / USB）
_DISK_INTERFACE_TYPES = ("IDE", "SCSI", "SATA", "NVMe", "RAID")


def _digits(value: str) -> str:
    """提取字符串中的数字部分（用于 MSFT_PhysicalDisk.DeviceId 归一化盘序）。"""
    return re.sub(r"\D", "", str(value))


def collect_wmi_surfaces() -> list[RawSurface]:
    """通过 WMI 采集多表面硬件标识符（仅 Windows）。"""
    if os.name != "nt":
        raise RuntimeError("WMI 采集仅支持 Windows 平台")

    import wmi  # 惰性导入，避免在非 Windows / 测试环境顶层失败

    c = wmi.WMI()
    surfaces: list[RawSurface] = []

    # 1. CPU ProcessorId
    try:
        for proc in c.Win32_Processor():
            pid = getattr(proc, "ProcessorId", None)
            if pid:
                surfaces.append(RawSurface("cpu", str(pid).strip(), "wmi"))
                break
    except Exception:
        pass

    # 2. 主板 序列号 + 型号
    try:
        for board in c.Win32_BaseBoard():
            serial = getattr(board, "SerialNumber", None)
            product = getattr(board, "Product", None)
            val = f"{serial or ''}{product or ''}".strip()
            if val:
                surfaces.append(RawSurface("board", val, "wmi"))
                break
    except Exception:
        pass

    # 3. BIOS 由原生 SMBIOS（Type0）独占：Win32_BIOS.SerialNumber 字段与 SMBIOS
    #    Type0 不对应（Type0 无 SerialNumber），交叉验证会误报 spoof，故此处不采。

    # 4. 系统 UUID
    try:
        for prod in c.Win32_ComputerSystemProduct():
            uuid = getattr(prod, "UUID", None)
            if uuid:
                surfaces.append(RawSurface("system_uuid", str(uuid).strip(), "wmi"))
                break
    except Exception:
        pass

    # 5. 内存 序列号（多值，按 DeviceLocator/BankLabel 区分槽位）
    try:
        for mem in c.Win32_PhysicalMemory():
            serial = getattr(mem, "SerialNumber", None)
            if serial:
                # slot 用序列号本身：DeviceLocator 在多 channel 主机上可能重复
                # （如同为 "DIMM 1"），用 serial 保证每根内存独立、不被误合并。
                surfaces.append(
                    RawSurface("memory", str(serial).strip(), "wmi", slot=normalize(str(serial)))
                )
    except Exception:
        pass

    # 6. 磁盘 Win32_DiskDrive（多值，盘序为 slot）
    try:
        for disk in c.Win32_DiskDrive():
            interface = getattr(disk, "InterfaceType", "") or ""
            if interface and interface not in _DISK_INTERFACE_TYPES:
                continue
            serial = getattr(disk, "SerialNumber", None)
            # 仅用 serial（与 storage_ioctl / MSFT_PhysicalDisk 一致），不拼 model——
            # 分量化交叉验证要求各源同字段，拼 model 会使同盘多源不一致、误报 spoof。
            val = str(serial).strip() if serial else ""
            if val:
                index = getattr(disk, "Index", None)
                slot = str(index) if index is not None else ""
                surfaces.append(RawSurface("disk", val, "wmi", slot=slot))
    except Exception:
        pass

    # 7. 磁盘 MSFT_PhysicalDisk（交叉源，盘序 DeviceId 数字部分为 slot）
    try:
        storage = wmi.WMI(moniker="//./root/Microsoft/Windows/Storage")
        for pd in storage.MSFT_PhysicalDisk():
            serial = getattr(pd, "SerialNumber", None)
            if serial:
                device_id = getattr(pd, "DeviceId", None)
                slot = _digits(str(device_id)) if device_id is not None else ""
                surfaces.append(RawSurface("disk", str(serial).strip(), "wmi", slot=slot))
    except Exception:
        pass

    # 8. MAC 地址（多值，物理网卡，排序取前 3 个；slot 为 MAC 本身以保持每个网卡独立）
    try:
        macs: list[str] = []
        for nic in c.Win32_NetworkAdapterConfiguration():
            mac = getattr(nic, "MACAddress", None)
            if mac:
                m = normalize(mac)
                if m and not is_placeholder(m):
                    macs.append(m)
        for m in sorted(set(macs))[:3]:
            surfaces.append(RawSurface("mac", m, "wmi", slot=m))
    except Exception:
        pass

    # 9. 机箱 序列号
    try:
        for ch in c.Win32_SystemEnclosure():
            serial = getattr(ch, "SerialNumber", None)
            if serial:
                surfaces.append(RawSurface("chassis", str(serial).strip(), "wmi"))
                break
    except Exception:
        pass

    # 10. TPM SpecVersion + ManufacturerVersion（root\CIMv2\Security\MicrosoftTpm）
    try:
        tpm_ns = wmi.WMI(namespace=r"root\CIMv2\Security\MicrosoftTpm")
        for t in tpm_ns.Win32_Tpm():
            spec = getattr(t, "SpecVersion", None) or ""
            mver = getattr(t, "ManufacturerVersion", None) or ""
            val = f"{spec}{mver}".strip()
            if val:
                surfaces.append(RawSurface("tpm", val, "tpm"))
                break
    except Exception:
        pass

    return surfaces
