# src/sealium/common/hardware/cross_validate.py
"""
原始表面值的清洗、交叉验证与 spoof 计分（纯逻辑，无 I/O）。

职责
----
1. **占位符过滤**：厂商占位符（``To be filled by O.E.M.`` / 全 0 / 全 F 等）视为无效，
   不产出分量；若是核心类，额外计 spoof 分。
2. **多源交叉验证**：同一 ``(category, slot)`` 的多个来源值，规范化后若不一致
   → 计 spoof 分（疑似某来源被 spoof 改动）。
3. **去重选代表**：每个 ``(category, slot)`` 只保留一个分量，来源按优先级选
   （原生 surface 优先于 WMI，因 spoof 更难改原生）。

``spoof_score`` 是软信号（客户端自报可伪造）。真正的 spoof 硬防线在
:func:`~sealium.common.fingerprint.matches` 的核心门槛：spoof 通常使核心类命中占位符
→ 核心分量缺失 → 核心匹配不足 → 自然判异机。
"""

from __future__ import annotations

from sealium.common.fingerprint import DEFAULT_WEIGHTS
from sealium.common.hardware.types import RawSurface

# 核心类集合（来自指纹默认权重表，单一真相）
_CORE_CATEGORIES: frozenset[str] = frozenset(
    spec.category for spec in DEFAULT_WEIGHTS if spec.is_core
)

# 来源优先级：数字越小越优先（原生 surface 优先，因 spoof 更难改）
_SOURCE_PRIORITY: dict[str, int] = {
    "smbios": 0,
    "storage_ioctl": 1,
    "tpm": 2,
    "wmi": 3,
}

# 占位符黑名单（均已是 normalize 后形态：upper + 去全部空白）
_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "NONE",
        "NULL",
        "UNKNOWN",
        "UNKNOWNS",
        "N/A",
        "NA",
        "DEFAULT",
        "DEFAULTSTRING",
        "DEFAULTSERIAL",
        "DEFAULTVERSION",
        "TOBEFILLEDBYO.E.M.",
        "TOBEFILLEDBYO.E.M",
        "TOBEFILLED",
        "NOTSPECIFIED",
        "NOTAVAILABLE",
        "NOTPRESENT",
        "NOTDEFINED",
        "SYSTEMPRODUCTNAME",
        "SYSTEMSERIALNUMBER",
        "SYSTEMVERSION",
        "SYSTEMSKUNUMBER",
        "SYSTEMFAMILY",
        "SYSTEMNAME",
        "BASEBOARDSERIALNUMBER",
        "OBSESSION",
    }
)


def normalize(raw: str) -> str:
    """规范化硬件原始值：trim → upper → 去全部空白。

    去全部空白是为了抹平来源间格式差异（如某些存储驱动返回的序列号每字符间插空格
    ``"WD  -W  C..."``，与 WMI 的 ``"WD-WCAY..."`` 规范化后一致），避免误报 spoof。
    """
    if raw is None:
        return ""
    s = str(raw).strip().upper()
    return "".join(s.split())


def _is_homogeneous(s: str, ch: str) -> bool:
    """是否由单一字符 ``ch`` 组成（长度 ≥4 才认定，避免短串误判）。"""
    return len(s) >= 4 and all(c == ch for c in s)


def is_placeholder(raw: str) -> bool:
    """是否为厂商占位符 / 无效值（normalize 后判定）。"""
    s = normalize(raw)
    if s in _PLACEHOLDERS:
        return True
    # 全 0 或全 F（UUID / MAC / 序列号的占位形态），忽略分隔符
    compact = s.replace("-", "").replace(":", "").replace("_", "").replace(".", "")
    if _is_homogeneous(compact, "0") or _is_homogeneous(compact, "F"):
        return True
    return False


def scrub_and_score(surfaces: list[RawSurface]) -> tuple[list[RawSurface], float]:
    """
    清洗原始表面值并计算 spoof 分。

    :param surfaces: 全部采集器产出的原始表面（含占位符、含多源）。
    :return: ``(去重后的代表分量列表, spoof_score)``。每个 ``(category, slot)``
             恰好一个分量，raw 已 normalize；spoof_score ∈ [0, 1]。
    """
    grouped: dict[tuple[str, str], list[tuple[str, str]]] = {}
    spoof = 0.0

    for sf in surfaces:
        if is_placeholder(sf.raw):
            # 占位符：核心类计 spoof，且不产出分量（防 spoof 值反通过核心门槛）
            if sf.category in _CORE_CATEGORIES:
                spoof = min(spoof + 0.1, 1.0)
            continue
        norm = normalize(sf.raw)
        if not norm:
            continue
        grouped.setdefault((sf.category, sf.slot), []).append((sf.source, norm))

    result: list[RawSurface] = []
    for (category, slot), entries in grouped.items():
        distinct = {raw for _, raw in entries}
        if len(distinct) > 1:
            # 多源不一致 → 强 spoof 信号
            spoof = min(spoof + 0.25, 1.0)
        # 选代表：来源优先级（原生优先）
        entries.sort(key=lambda se: _SOURCE_PRIORITY.get(se[0], 99))
        rep_source, rep_raw = entries[0]
        result.append(
            RawSurface(category=category, raw=rep_raw, source=rep_source, slot=slot)
        )

    return result, spoof
