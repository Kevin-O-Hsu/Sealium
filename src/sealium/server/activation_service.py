# src/sealium/server/activation_service.py
"""
激活业务核心。

将历史 ``activate`` 端点中与 HTTP/加密无关的业务逻辑抽离为纯领域服务：
输入 :class:`ActivationRequest`，输出 :class:`ActivationResponse`，不触碰任何
HTTP 或加密细节，全部依赖（存储、防重放、时间）均可注入，便于单测。

安全要点
--------
* 绑定原子性（HIGH-001）：状态转移 ``UNUSED -> USED`` 由存储层的条件 UPDATE
  单步完成；本服务据其布尔结果决定响应，杜绝并发抢绑导致“一码多机”。
* 错误信息不泄漏（GRAY-001）：对外将“码不存在”与“已被他机占用”合并为同一
  条通用提示，关闭激活码存在性枚举；具体原因写入服务端审计日志。
* 不回显原始敏感值（A09）：日志只记录激活码 / 机器码的短哈希。
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Callable, Optional

from sealium.common.fingerprint import (
    MachineFingerprint,
    MachineIdPolicy,
    matches,
    to_storage,
)
from sealium.common.models import ActivationCode, ActivationRequest, ActivationResponse
from sealium.server.database import ActivationCodeStorage
from sealium.server.replay_guard import ReplayGuard

NowProvider = Callable[[], datetime]

logger = logging.getLogger("sealium.server.activation")

# 对外统一的“不可用”提示：合并“不存在”与“被他机占用”，避免存在性枚举（GRAY-001）。
_CODE_UNAVAILABLE_MSG = "激活码无效或已被使用"


def _short_hash(value: str | MachineFingerprint) -> str:
    """用于日志的短哈希（截断），不记录原始激活码 / 机器码。"""
    s = value.canonical() if isinstance(value, MachineFingerprint) else str(value)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


class ActivationService:
    """激活业务服务。"""

    def __init__(
        self,
        storage: ActivationCodeStorage,
        replay_guard: ReplayGuard,
        timestamp_tolerance_seconds: int = 300,
        *,
        now_provider: Optional[NowProvider] = None,
        machine_id_policy: Optional[MachineIdPolicy] = None,
    ) -> None:
        self._storage = storage
        self._replay_guard = replay_guard
        self._tolerance = timestamp_tolerance_seconds
        self._now: NowProvider = now_provider or datetime.now
        self._policy = machine_id_policy or MachineIdPolicy.default()

    def process(self, request: ActivationRequest) -> ActivationResponse:
        """处理一次激活请求，返回（成功或错误的）响应。"""
        code = request.activation_code
        machine = request.machine_code
        nonce = request.nonce

        # 1. 激活码格式校验（非空字符串）
        if not (isinstance(code, str) and code):
            return ActivationResponse.error("激活码格式无效", nonce)

        now = self._now()

        # 2. 时间戳校验（防伪造 / 过期请求）
        if abs(int(now.timestamp()) - request.timestamp) > self._tolerance:
            logger.info("激活拒绝(时间戳) code=%s", _short_hash(code))
            return ActivationResponse.error("请求时间戳无效，请同步时间", nonce)

        # 3. 防重放检查
        if self._replay_guard.is_replay(code, request.nonce):
            logger.info("激活拒绝(重放) code=%s", _short_hash(code))
            return ActivationResponse.error("请求已被使用，请勿重复发送", nonce)

        # 4. 查询激活码
        record = self._storage.get_by_code(code)
        if record is None:
            logger.info("激活拒绝(不存在) code=%s", _short_hash(code))
            return ActivationResponse.error(_CODE_UNAVAILABLE_MSG, nonce)

        # 5. 已使用：同机幂等成功，异机拒绝（与“不存在”对外不可区分）
        if record.is_used():
            if record.bound_machine_code is not None and matches(
                record.bound_machine_code, machine, self._policy
            ):
                logger.info(
                    "激活成功(幂等) code=%s machine=%s",
                    _short_hash(code),
                    _short_hash(machine),
                )
                return ActivationResponse.success(
                    self._authorized_until(record), record.features, nonce
                )
            logger.info(
                "激活拒绝(他机) code=%s machine=%s",
                _short_hash(code),
                _short_hash(machine),
            )
            return ActivationResponse.error(_CODE_UNAVAILABLE_MSG, nonce)

        # 6. 过期检查
        if record.is_expired(now=now):
            logger.info("激活拒绝(过期) code=%s", _short_hash(code))
            return ActivationResponse.error("激活码已过期", nonce)

        # 7. 原子绑定：条件 UPDATE 保证仅一台机器能赢得绑定（HIGH-001）
        try:
            won = self._storage.bind_machine_code(code, to_storage(machine), now)
        except Exception:
            # 数据库异常：对外通用提示，不回显原始异常（LOW-003），内部记录详情
            logger.exception("绑定数据库异常 code=%s", _short_hash(code))
            return ActivationResponse.error("激活失败，请稍后重试", nonce)

        if won:
            logger.info(
                "激活成功(新绑定) code=%s machine=%s",
                _short_hash(code),
                _short_hash(machine),
            )
            return ActivationResponse.success(
                self._authorized_until(record), record.features, nonce
            )

        # 8. 绑定竞争失败：检查与抢绑之间被他人抢先。重读后判定。
        fresh = self._storage.get_by_code(code)
        if (
            fresh is not None
            and fresh.bound_machine_code is not None
            and matches(fresh.bound_machine_code, machine, self._policy)
        ):
            # 极端时序：恰好是本机抢到（同机并发重试），按幂等成功
            return ActivationResponse.success(
                self._authorized_until(record), record.features, nonce
            )
        logger.info(
            "激活拒绝(竞争落败) code=%s machine=%s",
            _short_hash(code),
            _short_hash(machine),
        )
        return ActivationResponse.error(_CODE_UNAVAILABLE_MSG, nonce)

    @staticmethod
    def _authorized_until(record: ActivationCode) -> str:
        return record.expires_at.strftime("%Y-%m-%d") if record.expires_at else "永久"
