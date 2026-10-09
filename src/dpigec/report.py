# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sorun raporu: ağ, ayarlar, sayaçlar, son kontrol sonuçları ve teşhis. Gezilen site adlarını içermez."""
from __future__ import annotations

import platform
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from . import __version__
from .config import PRESETS

TO = "gmtr244@gmail.com"

# Günlükten yalnızca servisin kendi durum satırları alınır; bağlantı satırları alınmaz.
_LOG_KEEP = ("SplitGate ", "stopped", "network ", "check", "method", "trying ", "failed to start",
             "could not", "transparent proxy listening", "DNS proxy listening", "warning")
# Yalnızca bu kaydedicilerin satırları alınır; ayrıca biçim "HH:MM:SS SEVİYE kaydedici: mesaj" olmalı
# (izleme/traceback satırları ve bağlantı kaydedicileri asla alınmaz).
_LOG_LOGGERS = ("dpigec", "dpigec.check", "dpigec.transparent", "dpigec.doh")
_LOG_LINE = re.compile(r"^\d\d:\d\d:\d\d (\w+) ([\w.]+): (.*)$")


def _os_name() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')[:80]
    except OSError:
        pass
    return platform.system()


def _filtered_log(lines: List[str]) -> List[str]:
    out = []
    for line in lines[-400:]:
        m = _LOG_LINE.match(line.rstrip())
        if not m or m.group(2) not in _LOG_LOGGERS:
            continue
        level, msg = m.group(1), m.group(3)
        if msg.startswith(_LOG_KEEP) or level in ("WARNING", "ERROR"):
            out.append(line.rstrip()[:200])
    return out[-60:]


def build(cfg: Dict[str, Any], status: Optional[Dict[str, Any]], note: str = "",
          log_lines: Optional[List[str]] = None) -> str:
    b: List[str] = []
    b.append(f"SplitGate (Linux) report {time.strftime('%Y-%m-%d %H:%M')}")
    b.append("")
    b.append("--- Problem (written by the user) ---")
    b.append(note.strip()[:4000] or "(not filled in)")
    b.append("")
    b.append(f"Version: {__version__}")
    b.append(f"System: {_os_name()} / kernel {platform.release()}")
    st = cfg["strategy"]
    b.append(f"Mode: {cfg['mode']}, preset: {st['preset']}, auto method: {cfg.get('auto_method', True)}")
    b.append(f"DNS: enabled={cfg['dns']['enabled']} providers={','.join(cfg['dns']['providers'])}")
    b.append(f"QUIC block: {cfg['quic_block']}, IPv6: {cfg['ipv6']}, gateway: {cfg['gateway']}")
    b.append(f"Test sites: {', '.join(cfg['probe_domains'])}")
    if status is None:
        b.append("Service: not running")
    else:
        s = status.get("stats", {})
        b.append(f"Service: {status.get('state')}  network: {status.get('network', '?')}")
        b.append(f"Check: {status.get('check', '?')} {status.get('check_detail', '')} "
                 f"verdict: {status.get('verdict', '')}  active method: {status.get('active_preset', '')}")
        b.append(f"Traffic: up {s.get('bytes_up', 0)} B, down {s.get('bytes_down', 0)} B, "
                 f"uptime {s.get('uptime', 0)} s")
        b.append(f"Connections: {s.get('conn_active', 0)} active / {s.get('conn_total', 0)} total, "
                 f"split TLS {s.get('tls_split', 0)} HTTP {s.get('http_split', 0)}, "
                 f"passthrough {s.get('passthrough', 0)}, errors {s.get('errors', 0)}")
        b.append(f"DNS: {s.get('dns_queries', 0)} queries, {s.get('dns_failed', 0)} failed, "
                 f"DoH ok {s.get('doh_ok', 0)} / fail {s.get('doh_fail', 0)}")
        if s.get("last_error"):
            b.append(f"Last error: {s['last_error']}")

    results = (status or {}).get("check_results") or []
    b.append("")
    b.append("--- Last check ---")
    if not results:
        b.append("no check yet")
    for r in results:
        label = PRESETS[r["preset"]]["label"] if r["preset"] in PRESETS else r.get("label", r["preset"])
        avg = f"  {r['avg_ms']} ms" if r.get("avg_ms") is not None else ""
        b.append(f"{label:<24} {r['ok']}/{r['total']}{avg}")
        for name, d in r.get("domains", {}).items():
            b.append(f"    {name}: " + (f"ok {d.get('ms')} ms" if d.get("ok") else str(d.get("code") or d.get("err"))))

    b.append("")
    b.append("--- Log (connection lines removed) ---")
    b.extend(_filtered_log(log_lines or []))
    return "\n".join(b) + "\n"


def mailto(body: str, subject: str) -> str:
    """mailto: adresi; çok uzun gövdeler bazı e-posta uygulamalarında kesilir, bu yüzden 6000 karakterle sınırlanır."""
    q = urllib.parse.urlencode({"subject": subject, "body": body[:6000]}, quote_via=urllib.parse.quote)
    return f"mailto:{TO}?{q}"
