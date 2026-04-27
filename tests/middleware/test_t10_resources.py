"""Tests for T10 middleware: BudgetEnforcer, LoopDetector, HeartbeatMonitor."""
from __future__ import annotations

import threading
import time

import pytest

from cosai_mcp.middleware.resources import (
    BudgetEnforcer,
    BudgetExceededError,
    HeartbeatMonitor,
    LoopDetector,
    MissingHeartbeatError,
    RecursiveLoopError,
)


# ===========================================================================
# BudgetEnforcer
# ===========================================================================

class TestBudgetEnforcer:

    def test_budget_enforcer_allows_within_limit(self):
        enforcer = BudgetEnforcer(max_calls=10)
        for _ in range(9):
            enforcer.record_call()
        assert enforcer.call_count == 9

    def test_budget_enforcer_rejects_at_limit(self):
        enforcer = BudgetEnforcer(max_calls=10)
        for _ in range(10):
            enforcer.record_call()
        with pytest.raises(BudgetExceededError):
            enforcer.record_call()  # 11th call

    def test_budget_enforcer_rejects_on_exact_exceed(self):
        enforcer = BudgetEnforcer(max_calls=3)
        enforcer.record_call()
        enforcer.record_call()
        enforcer.record_call()
        with pytest.raises(BudgetExceededError):
            enforcer.record_call()

    def test_call_count_increments(self):
        enforcer = BudgetEnforcer(max_calls=100)
        assert enforcer.call_count == 0
        enforcer.record_call()
        assert enforcer.call_count == 1
        enforcer.record_call()
        assert enforcer.call_count == 2

    def test_budget_wall_time_exceeded(self):
        enforcer = BudgetEnforcer(max_calls=1000, max_wall_seconds=0.01)
        enforcer.record_call()  # starts the clock
        time.sleep(0.05)
        with pytest.raises(BudgetExceededError, match="wall time"):
            for _ in range(100):
                enforcer.record_call()

    def test_budget_zero_wall_time_means_no_time_limit(self):
        enforcer = BudgetEnforcer(max_calls=100, max_wall_seconds=0.0)
        for _ in range(50):
            enforcer.record_call()
        # Should not raise even after a delay
        assert enforcer.call_count == 50

    def test_budget_error_message_includes_count(self):
        enforcer = BudgetEnforcer(max_calls=2)
        enforcer.record_call()
        enforcer.record_call()
        with pytest.raises(BudgetExceededError, match="3"):
            enforcer.record_call()

    def test_budget_thread_safe(self):
        enforcer = BudgetEnforcer(max_calls=100)
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(5):
                    enforcer.record_call()
            except BudgetExceededError:
                pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ===========================================================================
# LoopDetector
# ===========================================================================

class TestLoopDetector:

    def test_loop_detector_allows_shallow_chain(self):
        detector = LoopDetector(max_depth=5)
        detector.record_call("a", parent_id=None)
        detector.record_call("b", parent_id="a")
        depth = detector.record_call("c", parent_id="b")
        assert depth == 3

    def test_loop_detector_rejects_deep_chain(self):
        detector = LoopDetector(max_depth=5)
        ids = [f"e{i}" for i in range(6)]
        for i, eid in enumerate(ids):
            parent = ids[i - 1] if i > 0 else None
            if i < 5:
                detector.record_call(eid, parent_id=parent)
            else:
                with pytest.raises(RecursiveLoopError):
                    detector.record_call(eid, parent_id=parent)

    def test_loop_detector_root_depth_is_one(self):
        detector = LoopDetector(max_depth=10)
        depth = detector.record_call("root", parent_id=None)
        assert depth == 1

    def test_loop_detector_returns_depth(self):
        detector = LoopDetector(max_depth=10)
        detector.record_call("a", None)
        detector.record_call("b", "a")
        d = detector.record_call("c", "b")
        assert d == 3

    def test_loop_detector_independent_chains(self):
        """Two separate root chains should not interfere."""
        detector = LoopDetector(max_depth=3)
        detector.record_call("root1", None)
        detector.record_call("root2", None)
        detector.record_call("child1", "root1")
        detector.record_call("child2", "root2")
        # Each chain is depth 2 — should not exceed limit=3
        assert True

    def test_loop_detector_cycle_guard(self):
        """A corrupted parent chain with a cycle should not infinite-loop."""
        detector = LoopDetector(max_depth=100)
        # Inject a cycle manually
        detector._parents["x"] = "y"
        detector._parents["y"] = "x"
        # Should terminate (cycle guard)
        depth = detector._compute_depth("x")
        assert depth >= 1

    def test_loop_detector_error_message_includes_depth(self):
        detector = LoopDetector(max_depth=2)
        detector.record_call("a", None)
        detector.record_call("b", "a")
        with pytest.raises(RecursiveLoopError, match="3"):
            detector.record_call("c", "b")


# ===========================================================================
# HeartbeatMonitor
# ===========================================================================

class TestHeartbeatMonitor:

    def test_heartbeat_monitor_passes_with_progress(self):
        monitor = HeartbeatMonitor()
        t = threading.Thread(
            target=lambda: (time.sleep(0.05), monitor.notify_progress("echo"))
        )
        t.start()
        monitor.expect_progress("echo", timeout_seconds=2.0)
        t.join()

    def test_heartbeat_monitor_fails_without_progress(self):
        monitor = HeartbeatMonitor()
        with pytest.raises(MissingHeartbeatError):
            monitor.expect_progress("slow_tool", timeout_seconds=0.05)

    def test_heartbeat_monitor_notify_before_expect(self):
        monitor = HeartbeatMonitor()
        monitor.notify_progress("fast_tool")
        monitor.expect_progress("fast_tool", timeout_seconds=0.01)

    def test_heartbeat_monitor_reset_clears_event(self):
        monitor = HeartbeatMonitor()
        monitor.notify_progress("tool")
        monitor.reset("tool")
        with pytest.raises(MissingHeartbeatError):
            monitor.expect_progress("tool", timeout_seconds=0.05)

    def test_heartbeat_monitor_error_includes_tool_name(self):
        monitor = HeartbeatMonitor()
        with pytest.raises(MissingHeartbeatError, match="my_slow_tool"):
            monitor.expect_progress("my_slow_tool", timeout_seconds=0.01)

    def test_heartbeat_independent_tools(self):
        monitor = HeartbeatMonitor()
        monitor.notify_progress("tool_a")
        monitor.expect_progress("tool_a", timeout_seconds=0.1)
        with pytest.raises(MissingHeartbeatError):
            monitor.expect_progress("tool_b", timeout_seconds=0.05)

    def test_heartbeat_monitor_thread_safe(self):
        monitor = HeartbeatMonitor()
        errors: list[Exception] = []

        def notifier(name: str):
            try:
                time.sleep(0.01)
                monitor.notify_progress(name)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=notifier, args=(f"tool_{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for i in range(10):
            monitor.expect_progress(f"tool_{i}", timeout_seconds=1.0)
        assert not errors
