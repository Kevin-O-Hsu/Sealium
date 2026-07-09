# src/sealium/server/activation_service.py
"""
激活业务核心。

将历史 ``activate`` 端点中与 HTTP/加密无关的业务逻辑抽离为纯领域服务：
输入 :class:`ActivationRequest`，输出 :class:`ActivationResponse`，不触碰任何
HTTP 或加密细节，全部依赖（存储、防重放、时间）均可注入，便于单测。
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from sealium.common.models import ActivationCode, ActivationRequest, ActivationResponse
from sealium.server.database import ActivationCodeStorage
from sealium.server.replay_guard import ReplayGuard

NowProvider = Callable[[], datetime]


class ActivationService:
    """激活业务服务。"""

    def __init__(
        self,
        storage: ActivationCodeStorage,
        replay_guard: ReplayGuard,
        timestamp_tolerance_seconds: int = 300,
        *,
        now_provider: Optional[NowProvider] = None,
    ) -> None:
        self._storage = storage
        self._replay_guard = replay_guard
        self._tolerance = timestamp_tolerance_seconds
        self._now: NowProvider = now_provider or datetime.now

    def process(self, request: ActivationRequest) -> ActivationResponse:
        """处理一次激活请求，返回（成功或错误的）响应。"""
        code = request.activation_code

        # 1. 激活码格式校验（非空字符串）
        if not (isinstance(code, str) and code):
            return ActivationResponse.error("激活码格式无效")

        now = self._now()

        # 2. 时间戳校验（防伪造 / 过期请求）
        if abs(int(now.timestamp()) - request.timestamp) > self._tolerance:
            return ActivationResponse.error("请求时间戳无效，请同步时间")

        # 3. 防重放检查
        if self._replay_guard.is_replay(code, request.nonce):
            return ActivationResponse.error("请求已被使用，请勿重复发送")

        # 4. 查询激活码
        record = self._storage.get_by_code(code)
        if record is None:
            return ActivationResponse.error("激活码不存在")

        # 5. 已使用：同机幂等成功，异机拒绝
        if record.is_used():
            if record.bound_machine_code == request.machine_code:
                return ActivationResponse.success(
                    self._authorized_until(record), record.features, request.nonce
                )
            return ActivationResponse.error("激活码已被其他设备使用")

        # 6. 过期检查
        if record.is_expired(now=now):
            return ActivationResponse.error("激活码已过期")

        # 7. 绑定机器码
        try:
            self._storage.bind_machine_code(code, request.machine_code, now)
        except Exception as e:
            return ActivationResponse.error(f"数据库更新失败: {e}")

        # 8. 成功
        return ActivationResponse.success(
            self._authorized_until(record), record.features, request.nonce
        )

    @staticmethod
    def _authorized_until(record: ActivationCode) -> str:
        return record.expires_at.strftime("%Y-%m-%d") if record.expires_at else "永久"
