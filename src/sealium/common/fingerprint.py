# src/sealium/common/fingerprint.py
"""
机器指纹核心抽象与匹配算法（纯算法层，无 I/O、无 WMI）。

设计要点
--------
* 与采集解耦：本模块只定义「指纹长什么样」和「两枚指纹是否同一台机器」，
  不含任何硬件采集逻辑（采集在 :mod:`sealium.common.hardware`）。
* 客户端与服务端共用：客户端用它组装 :class:`MachineFingerprint`，
  服务端用它做 :func:`matches` 比对与存储序列化。服务端**不重算 value**（不持有
  pepper），只比对已哈希的分量——故 pepper 仅在客户端生成 value 时有意义。
* **逐项哈希而非聚合**：每类硬件单独哈希成 :attr:`Component.value`，才能做
  「加权部分匹配」，实现「换少量硬件仍认同一台」。旧的整体哈希（任一硬件变整码变）
  已彻底废弃。
* ``MachineFingerprint`` 是 ``machine_code`` 的唯一载体（breaking，无 str 形态、
  无 legacy、无跨格式桥接）。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# pepper：仅客户端生成 value 时用
# ---------------------------------------------------------------------------
# 固定 pepper 充当域分隔符，阻挡简单彩虹表。**绝不能用随机盐**——否则同机两次
# 激活产生不同 value，既破坏幂等又破坏 DB bound 比对（复刻 MEDIUM-003）。
# 部署后**不可变**：改它 = 全部已绑定记录的 value 失配 → 强制重激活。
# 仅客户端读它；服务端 import 本模块但不调用 hash_component，pepper 对服务端无意义。
_PEPPER = os.environ.get("MACHINE_ID_PEPPER", "sealium-v1-hardware-fingerprint-pepper")


def hash_component(category: str, raw: str, *, pepper: Optional[str] = None) -> str:
    """
    逐项哈希：``sha256(category + pepper + normalized_raw)``。

    :param category: 硬件类别（入哈希防不同类同值碰撞）。
    :param raw: 已规范化的硬件原始值。
    :param pepper: 域分隔盐；为 ``None`` 时用模块默认 ``_PEPPER``。测试可注入固定值。
    :return: 64 位十六进制哈希。绝不存原始串号。
    """
    p = pepper if pepper is not None else _PEPPER
    material = f"{category}:{p}:{raw}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


# ---------------------------------------------------------------------------
# 类别策略
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CategorySpec:
    """单个硬件类别的匹配策略。"""

    category: str
    weight: float
    is_core: bool
    multi: bool = False  # 多值类（disk/mac/memory）：按集合重叠率算相似度


# 默认权重表：核心和 0.95 / 外围和 0.05 / 总 1.00。
# 核心类（cpu/board/bios/system_uuid）权重高、漂移门槛严；外围类允许更换。
DEFAULT_WEIGHTS: tuple[CategorySpec, ...] = (
    CategorySpec("cpu", 0.30, True),
    CategorySpec("board", 0.25, True),
    CategorySpec("bios", 0.20, True),
    CategorySpec("system_uuid", 0.15, True),
    CategorySpec("disk", 0.05, False, multi=True),
    CategorySpec("mac", 0.03, False, multi=True),
    CategorySpec("memory", 0.01, False, multi=True),
    CategorySpec("tpm", 0.005, False),
    CategorySpec("chassis", 0.005, False),
)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Component:
    """单个硬件分量（类别 + 逐项哈希值 + 是否核心）。"""

    category: str
    value: str  # hash_component 输出，绝不存原始串号
    is_core: bool

    def to_dict(self) -> dict:
        return {"c": self.category, "h": self.value, "core": self.is_core}

    @classmethod
    def from_dict(cls, d: dict) -> "Component":
        if not isinstance(d, dict):
            raise ValueError("分量必须是 JSON 对象")
        category = d.get("c")
        value = d.get("h")
        if not (isinstance(category, str) and category):
            raise ValueError("分量类别非法")
        if not (isinstance(value, str) and value):
            raise ValueError("分量值非法")
        return cls(category=category, value=value, is_core=bool(d.get("core", False)))


@dataclass(frozen=True)
class MachineFingerprint:
    """
    机器指纹：多个硬件分量 + 采集期交叉验证的 spoof 分。

    ``spoof_score`` 是软信号（客户端自报、可被伪造为 0）。真正的 spoof 硬防线
    靠 :func:`matches` 的核心门槛（spoof 通常伴随核心类占位符 → 核心分量缺失
    → 核心匹配不足 → 自然判异机）。
    """

    version: int = 1
    components: tuple[Component, ...] = ()
    spoof_score: float = 0.0

    def by_category(self) -> dict[str, list[Component]]:
        """按类别索引（同类可能多值，如多块盘 / 多根内存）。"""
        result: dict[str, list[Component]] = {}
        for comp in self.components:
            result.setdefault(comp.category, []).append(comp)
        return result

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "components": [c.to_dict() for c in self.components],
            "spoof": self.spoof_score,
        }

    def canonical(self) -> str:
        """确定性 JSON（排序键、紧凑），用于日志短哈希与确定性比较。"""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict) -> "MachineFingerprint":
        """
        从字典（wire / DB JSON）重建指纹，严格校验。

        :raises ValueError: 非对象、版本不支持、缺字段、spoof 越界、无分量等。
        """
        if not isinstance(d, dict):
            raise ValueError("指纹必须是 JSON 对象")
        version = d.get("v")
        if version != 1:
            raise ValueError(f"不支持的指纹版本: {version!r}")
        raw_components = d.get("components")
        if not isinstance(raw_components, list):
            raise ValueError("指纹 components 必须是数组")
        components = tuple(Component.from_dict(c) for c in raw_components)
        if not components:
            raise ValueError("指纹至少需要一个分量")
        try:
            spoof = float(d.get("spoof", 0.0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"spoof_score 非法: {exc}") from exc
        if spoof < 0.0 or spoof > 1.0:
            raise ValueError("spoof_score 必须在 [0, 1] 范围")
        return cls(version=1, components=components, spoof_score=spoof)


# ---------------------------------------------------------------------------
# 匹配策略
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MachineIdPolicy:
    """同机判定策略。"""

    threshold: float = 0.70  # 加权相似度门槛
    core_min: int = 3  # 核心类最少匹配数
    spoof_max: float = 0.5  # spoof 超此直接拒
    weights: tuple[CategorySpec, ...] = DEFAULT_WEIGHTS

    @classmethod
    def default(cls) -> "MachineIdPolicy":
        return cls()


def _category_similarity(
    bound: list[Component], incoming: list[Component], spec: CategorySpec
) -> float:
    """
    单类相似度。

    * 单值类：值相等 1.0，否则 0.0。
    * 多值类（disk/mac/memory）：交集占 **bound**（已绑定基准）的比例——
      这样「加硬盘」（基准盘都在）sim=1.0 完全容忍，「换硬盘」部分容忍。
    """
    if not bound or not incoming:
        return 0.0
    if spec.multi:
        bset = {c.value for c in bound}
        iset = {c.value for c in incoming}
        if not bset or not iset:
            return 0.0
        return len(bset & iset) / len(bset)
    return 1.0 if bound[0].value == incoming[0].value else 0.0


def matches(
    bound: MachineFingerprint, incoming: MachineFingerprint, policy: MachineIdPolicy
) -> bool:
    """
    判定 ``incoming`` 是否与已绑定的 ``bound`` 属同一台机器。

    双门槛：核心类匹配数 ≥ ``core_min`` **且** 加权相似度 ≥ ``threshold``。
    spoof 先决：``incoming.spoof_score > spoof_max`` 直接判否（单一决策入口，
    覆盖幂等路径与竞争落败重判路径）。
    """
    if incoming.spoof_score > policy.spoof_max:
        return False
    bmap = bound.by_category()
    imap = incoming.by_category()
    weighted_sum = 0.0
    matched_core = 0
    for spec in policy.weights:
        sim = _category_similarity(bmap.get(spec.category, []), imap.get(spec.category, []), spec)
        weighted_sum += spec.weight * sim
        if spec.is_core and sim >= 1.0:
            matched_core += 1
    return matched_core >= policy.core_min and weighted_sum >= policy.threshold


def to_storage(fp: MachineFingerprint) -> str:
    """规范化为 DB TEXT（确定性 JSON）。"""
    return fp.canonical()
