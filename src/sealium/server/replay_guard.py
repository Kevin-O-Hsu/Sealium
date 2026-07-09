# src/sealium/server/replay_guard.py
"""
防重放守护。

基于 ``(activation_code, nonce)`` 组合去重。默认内存存储在超过上限时清空
（与历史行为一致）；存储可注入，便于测试或替换为持久化实现。
"""

from __future__ import annotations

from typing import Optional, Protocol

ReplayKey = tuple[str, str]


class ReplayStore(Protocol):
    """防重放存储协议。``seen`` 记录并返回该 key 是否已出现过。"""

    def seen(self, key: ReplayKey) -> bool: ...


class InMemoryReplayStore:
    """内存防重放存储：超限时整体清空。"""

    def __init__(self, max_size: int = 10000) -> None:
        self._seen: set[ReplayKey] = set()
        self._max_size = max_size

    def seen(self, key: ReplayKey) -> bool:
        if key in self._seen:
            return True
        self._seen.add(key)
        if len(self._seen) > self._max_size:
            self._seen.clear()
        return False

    def clear(self) -> None:
        self._seen.clear()


class ReplayGuard:
    """防重放守护，封装存储交互。"""

    def __init__(
        self, store: Optional[ReplayStore] = None, max_size: int = 10000
    ) -> None:
        self._store: ReplayStore = store if store is not None else InMemoryReplayStore(max_size)

    def is_replay(self, activation_code: str, nonce: str) -> bool:
        """检查并记录该 (activation_code, nonce) 是否为重放。"""
        return self._store.seen((activation_code, nonce))
