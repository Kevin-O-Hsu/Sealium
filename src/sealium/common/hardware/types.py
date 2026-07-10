# src/sealium/common/hardware/types.py
"""
硬件采集层的共享数据结构。

:class:`RawSurface` 是采集器产出的「原始表面值」——尚未哈希、尚未交叉验证。
经 :mod:`sealium.common.hardware.cross_validate` 清洗/计分后，由
:mod:`sealium.common.machine_code` 逐项哈希为 :class:`~sealium.common.fingerprint.Component`。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RawSurface:
    """单个采集来源的原始硬件值。

    :param category: 硬件类别（cpu/board/bios/system_uuid/disk/mac/memory/tpm/chassis）。
    :param raw: 原始值（采集后、规范化前）。
    :param source: 采集来源标记（smbios/storage_ioctl/wmi/tpm），用于交叉验证。
    :param slot: 物理槽位标识（多值类关联同一物理设备用，如 disk 的盘序 ``"0"``）；
                 单值类为空串。
    """

    category: str
    raw: str
    source: str
    slot: str = ""
