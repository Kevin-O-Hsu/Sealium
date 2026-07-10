# src/sealium/server/rate_limit.py
"""
请求速率限制。

采用固定窗口计数器（按 key 聚合，默认 key 为客户端 IP）。设计上与
``replay_guard`` 保持一致：小型、可注入、进程内、可注入 ``now_provider`` 便于
测试。默认对所有激活请求生效，抑制滥用与重放缓存冲刷攻击（MEDIUM-002）。

.. note::
   与防重放同理，本实现为进程内：多 worker 部署各进程独立计数。若需全局精确
   限流，可注入共享后端（如 Redis）。对当前单实例或弱一致限流场景已足够。
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Protocol


class RateLimiter(Protocol):
    """速率限制器协议。``allow`` 返回该 key 是否仍可在当前窗口内放行。"""

    window_seconds: int

    def allow(self, key: str) -> bool: ...


class InMemoryRateLimiter:
    """
    固定窗口速率限制器（线程安全）。

    每个 key 在 ``window_seconds`` 窗口内最多放行 ``max_requests`` 次；窗口
    滚动后计数重置。过期窗口惰性回收。
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        now_provider: Optional[Callable[[], float]] = None,
    ) -> None:
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests 与 window_seconds 必须为正整数")
        self._max = max_requests
        self.window_seconds = window_seconds
        self._now = now_provider or time.monotonic
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._now()
        with self._lock:
            window_start, count = self._buckets.get(key, (now, 0))
            if now - window_start >= self.window_seconds:
                window_start, count = now, 0
            count += 1
            self._buckets[key] = (window_start, count)
            # 惰性回收：桶数过多时丢弃已过期项，避免长期累积
            if len(self._buckets) > 4096:
                self._buckets = {
                    k: v for k, v in self._buckets.items() if now - v[0] < self.window_seconds
                }
            return count <= self._max


class NullRateLimiter:
    """不限流（用于显式关闭限流的部署 / 测试）。"""

    window_seconds = 1

    def allow(self, key: str) -> bool:  # noqa: D401 - 始终放行
        return True
