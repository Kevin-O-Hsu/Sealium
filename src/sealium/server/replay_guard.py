# src/sealium/server/replay_guard.py
"""
防重放守护。

基于 ``(activation_code, nonce)`` 组合去重。默认内存存储采用 **LRU + TTL** 逐条
淘汰（HIGH-002）：超限时只驱逐最旧的一条，而非整体清空——整体清空会让所有历史
nonce 瞬间重新可重放，攻击者只需灌满缓存即可击穿防重放。存储可注入，便于测试
或替换为跨进程的持久化实现。

.. note::
   内存存储按进程隔离：多 worker 部署下各进程各自一份，重启即丢失。生产环境
   若需跨进程一致的防重放，应注入共享后端（如 Redis）。
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Callable, Optional, Protocol

ReplayKey = tuple[str, str]

# 默认 TTL：覆盖两倍时间戳容忍窗口，保证窗口内的重放必被拦截。
_DEFAULT_TTL_SECONDS = 600


class ReplayStore(Protocol):
    """防重放存储协议。``seen`` 记录并返回该 key 是否已出现过。"""

    def seen(self, key: ReplayKey) -> bool: ...


class InMemoryReplayStore:
    """
    内存防重放存储：LRU + TTL 逐条淘汰。

    * 同一 key 在 TTL 内再次出现 -> 视为重放（返回 True）。
    * 超过 ``max_size`` 时驱逐最旧的一条（``popitem(last=False)``），绝不整体清空。
    * 过期条目惰性回收。
    """

    def __init__(
        self,
        max_size: int = 10000,
        ttl_seconds: Optional[int] = _DEFAULT_TTL_SECONDS,
        now_provider: Optional[Callable[[], float]] = None,
    ) -> None:
        self._seen: "OrderedDict[ReplayKey, float]" = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._now = now_provider or time.monotonic

    def seen(self, key: ReplayKey) -> bool:
        now = self._now()

        existing = self._seen.get(key)
        if existing is not None:
            # 未过期 -> 重放；已过期 -> 视为新（覆盖写入）
            if self._ttl is None or now - existing < self._ttl:
                return True

        self._seen[key] = now
        self._seen.move_to_end(key)  # 标记为最近使用

        # 惰性回收过期条目，再按容量驱逐最旧
        self._evict_expired(now)
        while len(self._seen) > self._max_size:
            self._seen.popitem(last=False)  # LRU：驱逐最旧的一条

        return False

    def _evict_expired(self, now: float) -> None:
        if self._ttl is None:
            return
        # OrderedDict 按插入/移动顺序；从头扫描过期项
        stale = []
        for k, ts in self._seen.items():
            if now - ts >= self._ttl:
                stale.append(k)
            else:
                break  # 后续更新时间不会更早
        for k in stale:
            self._seen.pop(k, None)

    def clear(self) -> None:
        self._seen.clear()


class ReplayGuard:
    """防重放守护，封装存储交互。"""

    def __init__(
        self,
        store: Optional[ReplayStore] = None,
        max_size: int = 10000,
        ttl_seconds: Optional[int] = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._store: ReplayStore = (
            store
            if store is not None
            else InMemoryReplayStore(max_size=max_size, ttl_seconds=ttl_seconds)
        )

    def is_replay(self, activation_code: str, nonce: str) -> bool:
        """检查并记录该 (activation_code, nonce) 是否为重放。"""
        return self._store.seen((activation_code, nonce))
