# src/sealium/common/hardware/__init__.py
"""
硬件采集包：统一入口 :func:`collect_surfaces`。

汇总原生表面（SMBIOS 固件表 + 磁盘 IOCTL，最难 spoof）与 WMI 多表面，返回原始
:class:`RawSurface` 列表（尚未清洗 / 交叉验证）。清洗、多源交叉验证、spoof 计分
在 :func:`cross_validate.scrub_and_score`。

采集器各自 fail-soft（任一来源失败只跳过该来源）；非 Windows 抛 ``RuntimeError``。
"""

from __future__ import annotations

from collections.abc import Callable

from sealium.common.hardware.cross_validate import scrub_and_score
from sealium.common.hardware.native_surfaces import collect_native_surfaces
from sealium.common.hardware.types import RawSurface
from sealium.common.hardware.wmi_surfaces import collect_wmi_surfaces

__all__ = ["RawSurface", "collect_surfaces", "scrub_and_score"]

SurfacesCollector = Callable[[], list[RawSurface]]


def collect_surfaces() -> list[RawSurface]:
    """
    汇总原生 + WMI 全部表面（原始、未清洗）。非 Windows 抛 ``RuntimeError``。

    每个采集器独立 fail-soft：原生表面失败（非平台原因）只跳过、不阻断 WMI；
    WMI 失败只跳过、不阻断原生。
    """
    surfaces: list[RawSurface] = []
    for collector in (collect_native_surfaces, collect_wmi_surfaces):
        try:
            surfaces.extend(collector())
        except RuntimeError:
            raise  # 平台错误向上传播
        except Exception:
            pass  # 单个采集器故障：fail-soft
    return surfaces
