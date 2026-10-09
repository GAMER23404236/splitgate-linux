"""Çalışma istatistikleri."""
from __future__ import annotations

import time
from typing import Any, Dict


class Stats:
    def __init__(self) -> None:
        self.started = time.time()
        self.conn_total = 0
        self.conn_active = 0
        self.tls_split = 0
        self.http_split = 0
        self.passthrough = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.errors = 0
        self.dns_queries = 0
        self.dns_cached = 0
        self.dns_failed = 0
        self.doh_ok = 0
        self.doh_fail = 0
        self.last_error = ""

    def conn_open(self) -> None:
        self.conn_total += 1
        self.conn_active += 1

    def conn_close(self) -> None:
        self.conn_active = max(0, self.conn_active - 1)

    def error(self, msg: str) -> None:
        self.errors += 1
        self.last_error = msg[:200]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "uptime": int(time.time() - self.started),
            "conn_total": self.conn_total,
            "conn_active": self.conn_active,
            "tls_split": self.tls_split,
            "http_split": self.http_split,
            "passthrough": self.passthrough,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "errors": self.errors,
            "dns_queries": self.dns_queries,
            "dns_cached": self.dns_cached,
            "dns_failed": self.dns_failed,
            "doh_ok": self.doh_ok,
            "doh_fail": self.doh_fail,
            "last_error": self.last_error,
        }
