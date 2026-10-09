"""Durum dosyası: motor yazar, GUI/CLI okur (yalnızca sayaçlar; alan adı yok)."""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Dict, Optional

from .config import STATUS_FILE


def write_status(data: Dict[str, Any], path: str = STATUS_FILE) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    data = dict(data, ts=time.time(), pid=os.getpid())
    fd, tmp = tempfile.mkstemp(prefix=".st-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def remove_status(path: str = STATUS_FILE) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def read_status(path: str = STATUS_FILE, max_age: float = 5.0) -> Optional[Dict[str, Any]]:
    """Taze bir durum varsa döndürür; yoksa (motor çalışmıyor) None."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if time.time() - data.get("ts", 0) > max_age:
        return None
    if data.get("state") == "stopped":
        return None
    return data
