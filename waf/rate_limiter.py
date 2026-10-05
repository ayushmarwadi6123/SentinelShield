import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        block_seconds: int
    ):
        if min(
            max_requests,
            window_seconds,
            block_seconds
        ) <= 0:
            raise ValueError(
                "Rate-limit settings must be positive"
            )

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        self._requests = defaultdict(deque)
        self._blocked_until = {}

        self._lock = threading.RLock()

    def check(self, ip: str) -> dict:

        now = time.monotonic()

        with self._lock:

            blocked_until = self._blocked_until.get(
                ip,
                0.0
            )

            if blocked_until > now:

                return {
                    "allowed": False,
                    "reason": "rate_limit",
                    "count": len(
                        self._requests[ip]
                    ),
                    "retry_after": max(
                        1,
                        int(
                            blocked_until - now
                        )
                    )
                }

            if blocked_until:
                self._blocked_until.pop(
                    ip,
                    None
                )

            q = self._requests[ip]

            cutoff = (
                now -
                self.window_seconds
            )

            while q and q[0] <= cutoff:
                q.popleft()

            q.append(now)

            if len(q) > self.max_requests:

                self._blocked_until[ip] = (
                    now +
                    self.block_seconds
                )

                return {
                    "allowed": False,
                    "reason": "rate_limit",
                    "count": len(q),
                    "retry_after":
                        self.block_seconds
                }

            return {
                "allowed": True,
                "reason": "ok",
                "count": len(q),
                "retry_after": 0
            }

    def snapshot(self) -> dict:

        now = time.monotonic()

        with self._lock:

            active = {}

            for ip, q in self._requests.items():

                cutoff = (
                    now -
                    self.window_seconds
                )

                active[ip] = sum(
                    ts > cutoff
                    for ts in q
                )

            return {
                "active_request_counts":
                    active,

                "blocked_ips": {
                    ip: max(
                        0,
                        int(until - now)
                    )
                    for ip, until
                    in self._blocked_until.items()
                    if until > now
                }
            }
