# src/sealium/common/machine_code.py
"""
机器码生成：组合 Windows 硬件标识符为分量指纹（``MachineFingerprint``）。

设计要点
--------
* 采集（:mod:`sealium.common.hardware`：原生 SMBIOS 固件表 + 磁盘 IOCTL + WMI 多表面，
  多源交叉验证）与指纹组装解耦：``generate_machine_code`` 接受可注入的 ``collector``，
  测试时可传入固定的 :class:`~sealium.common.hardware.RawSurface` 列表，无需真实硬件。
* 每类硬件**逐项哈希**（:func:`~sealium.common.fingerprint.hash_component`）成
  :class:`~sealium.common.fingerprint.Component`，组装为
  :class:`~sealium.common.fingerprint.MachineFingerprint`，支持服务端加权相似度匹配
  （换少量硬件仍认同一台）。旧的整体 SHA-256（任一硬件变整码变）已废弃。
* 不在模块顶层做任何 I/O，导入零副作用。
"""

from __future__ import annotations

from collections.abc import Callable

from sealium.common.exceptions import SealiumError
from sealium.common.fingerprint import (
    DEFAULT_WEIGHTS,
    Component,
    MachineFingerprint,
    hash_component,
)
from sealium.common.hardware import RawSurface, collect_surfaces, scrub_and_score

SurfacesCollector = Callable[[], "list[RawSurface]"]

# 类别 → 是否核心（来自指纹默认权重表，单一真相）
_CATEGORY_IS_CORE: dict[str, bool] = {
    spec.category: spec.is_core for spec in DEFAULT_WEIGHTS
}

# 核心类有效分量的宽松下限：低于此说明硬件特征过于稀疏（如虚拟机 / 精简系统）
_MIN_CORE_COMPONENTS = 2


def generate_machine_code(
    collector: SurfacesCollector | None = None,
    fallback_secret_provider: Callable[[], str] | None = None,
) -> MachineFingerprint:
    """
    生成机器码（分量指纹）。

    :param collector: 表面采集器；为 ``None`` 时用默认采集器（原生 + WMI，仅 Windows）。
                     测试时可注入返回固定 ``RawSurface`` 列表的采集器。
    :param fallback_secret_provider: 当核心类有效分量过少时的稳定补充来源（如每安装
                     随机密钥）。为 ``None`` 时 fail-safe 抛 :class:`SealiumError`，
                     而非生成不可靠指纹。
    :return: :class:`MachineFingerprint`。
    :raises RuntimeError: 非 Windows 平台（默认采集器仅 Windows 可用）。
    :raises SealiumError: 硬件特征过于稀疏且未提供 ``fallback_secret_provider``。
    """
    collect = collector if collector is not None else collect_surfaces
    raws = collect()
    clean, spoof = scrub_and_score(raws)

    components: list[Component] = []
    core_count = 0
    for sf in clean:
        is_core = _CATEGORY_IS_CORE.get(sf.category, False)
        components.append(Component(sf.category, hash_component(sf.category, sf.raw), is_core))
        if is_core:
            core_count += 1

    if core_count < _MIN_CORE_COMPONENTS:
        if fallback_secret_provider is None:
            raise SealiumError(
                "硬件特征过于稀疏（核心类有效分量 < 2），无法生成可靠机器码；"
                "请提供 fallback_secret_provider 或扩充硬件采集来源"
            )
        secret = str(fallback_secret_provider())
        # 注入为 system_uuid 核心分量，使核心门槛仍可达成（同安装稳定 → 可匹配）
        components.append(
            Component("system_uuid", hash_component("system_uuid", secret), True)
        )

    return MachineFingerprint(components=tuple(components), spoof_score=spoof)
