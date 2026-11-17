"""Real-time structured event logger for the persistent right-side Observation Panel."""

from collections import deque
from datetime import datetime
import re
import threading
from typing import Any, Dict, List, Optional


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "password_hash",
    "secret",
    "session_secret",
    "csrf_token",
    "token",
    "cookie",
    "authorization",
}


def sanitize_value(key: str, value: Any) -> Any:
    """Redact passwords, session secrets, and sensitive tokens from logs."""
    if any(sk in key.lower() for sk in SENSITIVE_KEYS):
        if isinstance(value, str) and value:
            return "***REDACTED***"
        return "***REDACTED***"
    if isinstance(value, dict):
        return sanitize_dict(value)
    if isinstance(value, str):
        # Mask any 64-char hex SHA-256 password hashes if embedded
        value = re.sub(r"\b[a-f0-9]{64}\b", "***HASH_REDACTED***", value)
    return value


def sanitize_dict(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data:
        return {}
    return {k: sanitize_value(k, v) for k, v in data.items()}


class LiveEventLogger:
    """Thread-safe in-memory event ring buffer per module for live execution telemetry."""

    def __init__(self, max_events_per_module: int = 120):
        self._lock = threading.Lock()
        self._max = max_events_per_module
        self._logs: Dict[str, deque] = {}
        self._counter = 0

    def log(
        self,
        module: str,
        category: str,
        title: str,
        message: str,
        *,
        mode: str = "info",
        method: Optional[str] = None,
        endpoint: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record an actual execution event.
        Categories: EXPLOIT_SUCCESS | MITIGATION_BLOCKED | WARNING | INFO | DB_OP | HTTP_REQ | HTTP_RES | SECURITY_CHECK | BROWSER_EXEC
        """
        with self._lock:
            self._counter += 1
            entry = {
                "id": self._counter,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "module": module,
                "category": category,
                "title": title,
                "message": message,
                "mode": mode,
                "method": method,
                "endpoint": endpoint,
                "params": sanitize_dict(params),
                "payload": payload,
                "details": sanitize_dict(details),
            }
            if module not in self._logs:
                self._logs[module] = deque(maxlen=self._max)
            self._logs[module].appendleft(entry)
            return entry

    def get_logs(self, module: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._logs.get(module, []))

    def clear_logs(self, module: str) -> None:
        with self._lock:
            if module in self._logs:
                self._logs[module].clear()


# Global singleton used across all modules and routes
event_logger = LiveEventLogger()
