# src/sealium/common/models.py
"""
共享数据模型（客户端与服务端共用）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

from sealium.common.fingerprint import MachineFingerprint


class ActivationStatus(IntEnum):
    """激活码状态。"""

    UNUSED = 0  # 未激活
    USED = 1  # 已激活


def _machine_id_to_wire(mid: MachineFingerprint | None) -> dict | None:
    """指纹 → wire dict（``None`` 透传）。"""
    if mid is None:
        return None
    return mid.to_dict()


def _machine_id_from_wire(data: object) -> MachineFingerprint | None:
    """wire dict → 指纹（``None`` 透传）。非 dict 抛 ``ValueError``。"""
    if data is None:
        return None
    if isinstance(data, dict):
        return MachineFingerprint.from_dict(data)
    raise ValueError("机器码必须是指纹对象（JSON 对象）")


@dataclass
class ActivationCode:
    """激活码记录（对应数据库一行）。"""

    activation_code: str
    bound_machine_code: MachineFingerprint | None = None
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    features: list[str] = field(default_factory=list)
    status: ActivationStatus = ActivationStatus.UNUSED

    def is_used(self) -> bool:
        """是否已被使用。"""
        return self.status == ActivationStatus.USED

    def is_expired(self, now: datetime | None = None) -> bool:
        """是否已过期。``now`` 可注入便于测试；默认取当前时间。"""
        if self.expires_at is None:
            return False
        current = now if now is not None else datetime.now()
        return current > self.expires_at

    def to_dict(self) -> dict:
        """转换为字典，便于 JSON 序列化。"""
        return {
            "activation_code": self.activation_code,
            "bound_machine_code": _machine_id_to_wire(self.bound_machine_code),
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "features": self.features,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ActivationCode:
        """从字典创建实例。"""
        return cls(
            activation_code=data["activation_code"],
            bound_machine_code=_machine_id_from_wire(data.get("bound_machine_code")),
            activated_at=(
                datetime.fromisoformat(data["activated_at"])
                if data.get("activated_at")
                else None
            ),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            features=data.get("features", []),
            status=ActivationStatus(data.get("status", 0)),
        )


@dataclass
class ActivationRequest:
    """客户端发送的激活请求（解密后的明文）。"""

    activation_code: str  # 用户输入的激活码
    machine_code: MachineFingerprint  # 机器码（硬件分量指纹）
    timestamp: int  # Unix 时间戳（秒）
    nonce: str  # 客户端随机数（十六进制字符串）

    def to_dict(self) -> dict:
        return {
            "activation_code": self.activation_code,
            "machine_code": _machine_id_to_wire(self.machine_code),
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ActivationRequest:
        """
        从字典创建实例，严格校验字段类型与基本格式（MEDIUM-004 / SMELL-002）。

        :raises ValueError: 字段缺失、类型非法或格式不合法时抛出，调用方据此返回错误。
        """
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")

        try:
            code = data["activation_code"]
            machine_raw = data["machine_code"]
            timestamp = data["timestamp"]
            nonce = data["nonce"]
        except KeyError as exc:
            raise ValueError(f"缺少必填字段: {exc.args[0]}") from exc

        if not (isinstance(code, str) and code):
            raise ValueError("activation_code 必须为非空字符串")
        if not isinstance(machine_raw, dict):
            raise ValueError("machine_code 必须是指纹对象")
        try:
            machine = MachineFingerprint.from_dict(machine_raw)
        except ValueError as e:
            raise ValueError(f"machine_code 非法: {e}") from e
        if not (isinstance(nonce, str) and nonce):
            raise ValueError("nonce 必须为非空字符串")

        # timestamp 必须为整数；兼容纯数字字符串（防御性转换），排除 bool。
        if isinstance(timestamp, bool):
            raise ValueError("timestamp 必须为整数")
        if isinstance(timestamp, int):
            pass
        elif isinstance(timestamp, str) and timestamp.lstrip("-").isdigit():
            timestamp = int(timestamp)
        else:
            raise ValueError("timestamp 必须为整数")

        return cls(
            activation_code=code,
            machine_code=machine,
            timestamp=timestamp,
            nonce=nonce,
        )


@dataclass
class ActivationResponse:
    """服务端返回的激活响应（加密前的明文）。"""

    result: str  # "success" 或 "error"
    authorized_until: str | None = None  # 授权截止日期（YYYY-MM-DD，永久为 "永久"）
    features: list[str] | None = None  # 授权功能列表
    nonce: str | None = None  # 回显客户端 nonce（防篡改）
    error_msg: str | None = None  # 错误信息（result 为 error 时）

    @classmethod
    def success(
        cls, authorized_until: str, features: list[str], nonce: str
    ) -> ActivationResponse:
        """创建成功响应。"""
        return cls(
            result="success",
            authorized_until=authorized_until,
            features=features,
            nonce=nonce,
        )

    @classmethod
    def error(cls, error_msg: str, nonce: str | None = None) -> ActivationResponse:
        """创建错误响应。"""
        return cls(result="error", error_msg=error_msg, nonce=nonce)

    def to_dict(self) -> dict:
        data = {"result": self.result}
        if self.authorized_until is not None:
            data["authorized_until"] = self.authorized_until
        if self.features is not None:
            data["features"] = self.features
        if self.nonce is not None:
            data["nonce"] = self.nonce
        if self.error_msg is not None:
            data["error_msg"] = self.error_msg
        return data

    @classmethod
    def from_dict(cls, data: dict) -> ActivationResponse:
        return cls(
            result=data["result"],
            authorized_until=data.get("authorized_until"),
            features=data.get("features"),
            nonce=data.get("nonce"),
            error_msg=data.get("error_msg"),
        )
