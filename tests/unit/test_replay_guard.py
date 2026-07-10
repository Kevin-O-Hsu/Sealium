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

    def test_overflow_evicts_oldest_only_not_all(self):
        """超限时仅驱逐最旧一条（LRU），绝非整体清空（HIGH-002）。"""
        store = InMemoryReplayStore(max_size=2)
        store.seen(("a", "1"))
        store.seen(("b", "1"))
        assert len(store._seen) == 2
        store.seen(("c", "1"))  # 超限 -> 仅驱逐最旧的 ("a","1")
        # 直接核对存储：仅最旧的 ("a","1") 被逐出，其余保留
        assert ("a", "1") not in store._seen
        assert ("b", "1") in store._seen
        assert ("c", "1") in store._seen
        assert len(store._seen) == 2

    def test_ttl_expiry_makes_key_new_again(self):
        """TTL 过期后，同一 key 不再视为重放。"""
        clock = [0.0]
        store = InMemoryReplayStore(ttl_seconds=10, now_provider=lambda: clock[0])
        assert store.seen(("a", "1")) is False
        assert store.seen(("a", "1")) is True  # 窗口内重放
        clock[0] += 11  # 超过 TTL
        assert store.seen(("a", "1")) is False  # 过期后重新视为新

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
