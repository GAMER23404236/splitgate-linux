"""Ayrıcalıklı yardımcıyı (dpigecctl) pkexec ile çağıran istemci - Qt'den bağımsız."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional

from .i18n import _, language

CTL_CANDIDATES = ("/usr/lib/dpigec/dpigecctl", "/usr/local/lib/dpigec/dpigecctl")
CTL = next((p for p in CTL_CANDIDATES if os.path.exists(p)), CTL_CANDIDATES[0])
UNIT = "dpigec.service"


def run_ctl(args, stdin_text: Optional[str] = None, timeout: int = 180) -> Dict[str, Any]:
    """dpigecctl komutunu çalıştırır; her zaman {'ok': bool, 'msg': str, ...} döndürür."""
    if os.path.exists(CTL):
        cmd = [CTL, "--lang", language(), *args]
    else:  # geliştirme ortamı: kurulum yapılmadan çalıştırma
        cmd = [sys.executable, "-m", "dpigec.ctl", "--lang", language(), *args]
    if os.geteuid() != 0:
        pk = shutil.which("pkexec")
        if not pk:
            return {"ok": False, "msg": _("pkexec not found (is polkit installed?)")}
        cmd = [pk, *cmd]
    try:
        res = subprocess.run(cmd, input=stdin_text, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": _("the operation timed out")}
    except OSError as e:
        return {"ok": False, "msg": _("could not run: {e}", e=e)}
    for line in reversed(res.stdout.strip().splitlines()):
        try:
            data = json.loads(line)
            if isinstance(data, dict) and "ok" in data:
                return data
        except ValueError:
            continue
    if res.returncode in (126, 127):
        return {"ok": False, "msg": _("Authorization was cancelled or denied.")}
    return {"ok": False, "msg": (res.stderr.strip()[-200:] or _("unexpected output"))}


def unit_active() -> Optional[bool]:
    """Servis şu an çalışıyor mu (ya da başlıyor mu)? (yetki gerekmez)"""
    exe = shutil.which("systemctl")
    if not exe:
        return None
    try:
        res = subprocess.run([exe, "is-active", UNIT], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.strip()
    if out in ("active", "activating", "reloading"):
        return True
    return False if out else None


def unit_enabled() -> Optional[bool]:
    """Servis açılışta başlatılacak şekilde etkin mi? (yetki gerekmez)"""
    exe = shutil.which("systemctl")
    if not exe:
        return None
    try:
        res = subprocess.run([exe, "is-enabled", UNIT], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.strip()
    if out == "enabled":
        return True
    if out in ("disabled", "static", "indirect", "masked", "not-found") or res.returncode:
        return False
    return None
