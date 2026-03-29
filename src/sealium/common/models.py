# src/sealium/common/models.py
"""
共享数据模型（客户端与服务端共用）
包含激活码信息、请求和响应模型
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import IntEnum


class ActivationStatus(IntEnum):
    """激活码状态枚举"""

    UNUSED = 0  # 未激活
    USED = 1  # 已激活


@dataclass
class ActivationCode:
    """
    激活码信息模型（对应数据库记录）
    """

    activation_code: str  # 激活码字符串
    bound_machine_code: Optional[str] = None  # 绑定的机器码，未绑定时为 None
    activated_at: Optional[datetime] = None  # 激活时间
    expires_at: Optional[datetime] = None  # 授权截止时间
    features: List[str] = field(default_factory=list)  # 授权功能列表（JSON 存储）
    status: ActivationStatus = ActivationStatus.UNUSED  # 激活状态

    def is_used(self) -> bool:
        """是否已被使用"""
        return self.status == ActivationStatus.USED

    def is_expired(self) -> bool:
        """是否已过期"""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于 JSON 序列化"""
        return {
            "activation_code": self.activation_code,
            "bound_machine_code": self.bound_machine_code,
            "activated_at": (
                self.activated_at.isoformat() if self.activated_at else None
            ),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "features": self.features,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActivationCode":
        """从字典创建实例"""
        return cls(
            activation_code=data["activation_code"],
            bound_machine_code=data.get("bound_machine_code"),
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
    """
    客户端发送的激活请求（解密后的明文）
    """

    activation_code: str  # 用户输入的激活码
    machine_code: str  # 机器码（硬件信息哈希）
    timestamp: int  # Unix 时间戳（秒）
    nonce: str  # 客户端随机数（十六进制字符串）

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "activation_code": self.activation_code,
            "machine_code": self.machine_code,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActivationRequest":
        """从字典创建实例"""
        return cls(
            activation_code=data["activation_code"],
            machine_code=data["machine_code"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
        )


@dataclass
class ActivationResponse:
    """
    服务端返回的激活响应（加密前的明文）
    """

    result: str  # "success" 或 "error"
    authorized_until: Optional[str] = None  # 授权截止日期（YYYY-MM-DD）
    features: Optional[List[str]] = None  # 授权功能列表
    nonce: Optional[str] = None  # 服务端随机数（防重放）
    error_msg: Optional[str] = None  # 错误信息（当 result 为 error 时）

    @classmethod
    def success(
        cls, authorized_until: str, features: List[str], nonce: str
    ) -> "ActivationResponse":
        """创建成功响应"""
        return cls(
            result="success",
            authorized_until=authorized_until,
            features=features,
            nonce=nonce,
        )

    @classmethod
    def error(cls, error_msg: str, nonce: Optional[str] = None) -> "ActivationResponse":
        """创建错误响应"""
        return cls(
            result="error",
            error_msg=error_msg,
            nonce=nonce,
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
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
    def from_dict(cls, data: Dict[str, Any]) -> "ActivationResponse":
        """从字典创建实例"""
        return cls(
            result=data["result"],
            authorized_until=data.get("authorized_until"),
            features=data.get("features"),
            nonce=data.get("nonce"),
            error_msg=data.get("error_msg"),
        )
