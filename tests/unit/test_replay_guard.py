# tests/unit/test_replay_guard.py
"""防重放守护单元测试。"""

from __future__ import annotations

from sealium.server.replay_guard import InMemoryReplayStore, ReplayGuard


class TestInMemoryReplayStore:
    def test_first_seen_is_new(self):
        store = InMemoryReplayStore()
        assert store.seen(("code", "nonce1")) is False
        assert store.seen(("code", "nonce1")) is True

    def test_different_keys_independent(self):
        store = InMemoryReplayStore()
        store.seen(("code", "n1"))
        assert store.seen(("code", "n2")) is False
        assert store.seen(("other", "n1")) is False

    def test_overflow_clears_store(self):
        store = InMemoryReplayStore(max_size=2)
        store.seen(("a", "1"))
        store.seen(("b", "1"))
        assert len(store._seen) == 2
        store.seen(("c", "1"))  # 超限 -> 整体清空
        # 清空后，曾经的 key 重新视为新
        assert store.seen(("a", "1")) is False

    def test_clear_method(self):
        store = InMemoryReplayStore()
        store.seen(("a", "1"))
        store.clear()
        assert store.seen(("a", "1")) is False


class TestReplayGuard:
    def test_is_replay_flag(self):
        guard = ReplayGuard()
        assert guard.is_replay("code", "n") is False
        assert guard.is_replay("code", "n") is True

    def test_inject_custom_store(self):
        seen_keys = []

        class SpyStore:
            def seen(self, key):
                seen_keys.append(key)
                return False

        guard = ReplayGuard(store=SpyStore())
        guard.is_replay("c", "n")
        assert ("c", "n") in seen_keys
