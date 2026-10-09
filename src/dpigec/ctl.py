# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ayrıcalıklı yardımcı (pkexec ile root olarak çalışır).

GUI ve CLI, root gerektiren her işi bu tek giriş noktasından yapar; böylece
polkit yalnızca bu programa izin verir. Çıktı her zaman tek satır JSON'dur.
Yapılandırma STDIN'den alınır (kullanıcının kontrolündeki dosya yolu değil).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from typing import Any, Dict

from . import firewall
from .i18n import _, set_language
from .config import SYSTEM_CONFIG, ConfigError, load_config, normalize, save_config

UNIT = "dpigec.service"
MAX_CONFIG_BYTES = 64 * 1024


def _out(ok: bool, **kw: Any) -> int:
    print(json.dumps(dict(ok=ok, **kw), ensure_ascii=False))
    return 0 if ok else 1


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    exe = shutil.which("systemctl") or "/usr/bin/systemctl"
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)


def _unit_cmd(action: str) -> int:
    res = _systemctl(action, UNIT)
    if res.returncode != 0:
        return _out(False, msg=(res.stderr or res.stdout).strip() or _("systemctl {action} failed", action=action))
    return _out(True, msg=_("{action} done", action=action))


def cmd_apply_config() -> int:
    raw = sys.stdin.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        return _out(False, msg=_("configuration is too large"))
    try:
        cfg = normalize(json.loads(raw))
        firewall.apply(cfg, check_only=True)  # nft söz dizimini önceden sına
        save_config(cfg, SYSTEM_CONFIG)
    except (ValueError, ConfigError) as e:
        return _out(False, msg=_("invalid configuration: {e}", e=e))
    except firewall.FirewallError as e:
        return _out(False, msg=str(e))
    return _out(True, msg=_("configuration saved"))


def cmd_probe() -> int:
    from .probe import best_preset, run_probe
    try:
        cfg = load_config(SYSTEM_CONFIG)
        # İsteğe bağlı: STDIN'de alan adı listesi (JSON dizi)
        domains = None
        if not sys.stdin.isatty():
            data = sys.stdin.read(4096).strip()
            if data:
                domains = normalize({"probe_domains": json.loads(data)})["probe_domains"]
        results = asyncio.run(run_probe(cfg, domains))
    except (ValueError, ConfigError) as e:
        return _out(False, msg=str(e))
    return _out(True, results=results, best=best_preset(results))


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) >= 2 and argv[0] == "--lang":
        set_language(argv[1])
        argv = argv[2:]
    if not argv:
        return _out(False, msg=_("usage: dpigecctl start|stop|restart|enable|disable|apply-config|probe|recheck|cleanup"))
    cmd = argv[0]
    if cmd in ("start", "stop", "restart", "enable", "disable"):
        return _unit_cmd(cmd)
    if cmd == "apply-config":
        return cmd_apply_config()
    if cmd == "probe":
        return cmd_probe()
    if cmd == "recheck":
        # Servise SIGUSR1: seçili yöntemi test sitelerinde yeniden dener.
        res = _systemctl("kill", "--signal=SIGUSR1", "--kill-whom=main", UNIT)
        if res.returncode != 0:
            return _out(False, msg=(res.stderr or res.stdout).strip() or _("systemctl {action} failed", action="kill"))
        return _out(True, msg=_("check started"))
    if cmd == "cleanup":
        removed = firewall.remove()
        return _out(True, msg=_("rules removed") if removed else _("no rules to remove"))
    return _out(False, msg=_("unknown command: {cmd}", cmd=cmd))


if __name__ == "__main__":
    sys.exit(main())
