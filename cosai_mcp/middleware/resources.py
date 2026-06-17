"""T10: Budget enforcement, recursive loop detection, heartbeat monitoring."""
from __future__ import annotations

import threading
import time


class BudgetExceededError(Exception):
    """Raised when a session exceeds the configured call-count or wall-time budget."""


class RecursiveLoopError(Exception):
    """Raised when a tool-call chain exceeds the configured depth limit."""


class MissingHeartbeatError(Exception):
    """Raised when a long-running tool fails to emit a progress notification in time."""


class BudgetEnforcer:
    """Count tools/call invocations and optionally wall-clock time per session.

    Thread-safe. Raises BudgetExceededError on the call that exceeds the limit.
    """

    def __init__(self, max_calls: int, max_wall_seconds: float = 0.0) -> None:
        self._max_calls = max_calls
        self._max_wall = max_wall_seconds
        self._call_count = 0
        self._start_time: float | None = None
        self._lock = threading.Lock()

    def record_call(self) -> None:
        """Record one tools/call. Raises BudgetExceededError if over limit."""
        with self._lock:
            if self._start_time is None:
                self._start_time = time.monotonic()
            self._call_count += 1
            if self._call_count > self._max_calls:
                raise BudgetExceededError(
                    f"Budget exceeded: {self._call_count} calls > max {self._max_calls}"
                )
            if self._max_wall > 0:
                elapsed = time.monotonic() - self._start_time
                if elapsed > self._max_wall:
                    raise BudgetExceededError(
                        f"Budget exceeded: wall time {elapsed:.1f}s > max {self._max_wall}s"
                    )

    @property
    def call_count(self) -> int:
        return self._call_count


class LoopDetector:
    """Track parent-ID chains in the audit log; raise when chain depth exceeds limit.

    Protects against recursive tool-call loops and Denial-of-Wallet attacks where
    one tool call triggers unbounded recursive LLM inference.

    Thread-safe.
    """

    def __init__(self, max_depth: int) -> None:
        self._max_depth = max_depth
        self._lock = threading.Lock()
        # entry_id -> parent_id
        self._parents: dict[str, str | None] = {}

    def record_call(self, entry_id: str, parent_id: str | None = None) -> int:
        """Record a call entry. Returns current chain depth.

        Raises RecursiveLoopError if the chain from *entry_id* back to the root
        exceeds *max_depth*.
        """
        with self._lock:
            self._parents[entry_id] = parent_id
            depth = self._compute_depth(entry_id)
            if depth > self._max_depth:
                raise RecursiveLoopError(
                    f"Recursive loop detected: chain depth {depth} > max {self._max_depth} "
                    f"(entry={entry_id!r}, parent={parent_id!r})"
                )
            return depth

    def _compute_depth(self, entry_id: str) -> int:
        depth = 1
        current = entry_id
        seen: set[str] = set()
        while True:
            parent = self._parents.get(current)
            if parent is None:
                break
            if parent in seen:
                break  # cycle guard — prevents infinite loop on corrupt state
            seen.add(current)
            current = parent
            depth += 1
        return depth


class HeartbeatMonitor:
    """Verify that a notifications/progress event arrives within a timeout window.

    Used to enforce that long-running tool calls emit progress signals, preventing
    silent hangs that tie up scanner budget.

    Thread-safe. Each tool_name has an independent event.
    """

    def __init__(self) -> None:
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def notify_progress(self, tool_name: str) -> None:
        """Signal that a notifications/progress event was received for *tool_name*."""
        with self._lock:
            if tool_name not in self._events:
                self._events[tool_name] = threading.Event()
        self._events[tool_name].set()

    def expect_progress(self, tool_name: str, timeout_seconds: float) -> None:
        """Block until a progress event arrives for *tool_name*.

        Raises MissingHeartbeatError if no event arrives within *timeout_seconds*.
        """
        with self._lock:
            if tool_name not in self._events:
                self._events[tool_name] = threading.Event()
        event = self._events[tool_name]
        if not event.wait(timeout=timeout_seconds):
            raise MissingHeartbeatError(
                f"No notifications/progress received for tool {tool_name!r} "
                f"within {timeout_seconds}s"
            )

    def reset(self, tool_name: str) -> None:
        """Clear the progress event for *tool_name* (reuse across multiple calls)."""
        with self._lock:
            if tool_name in self._events:
                self._events[tool_name].clear()
