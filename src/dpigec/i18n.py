# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interface language: English by default; translations are looked up by their English text."""
from __future__ import annotations

import importlib
import json
import os
import tempfile
from typing import Dict, Optional

LANGUAGES = {"en": "English", "tr": "Türkçe"}
DEFAULT_LANGUAGE = "en"

_current = DEFAULT_LANGUAGE
_catalog: Dict[str, str] = {}


def normalize_language(code: object) -> Optional[str]:
    return code if isinstance(code, str) and code in LANGUAGES else None


def set_language(code: object) -> str:
    global _current, _catalog
    code = normalize_language(code) or DEFAULT_LANGUAGE
    if code == DEFAULT_LANGUAGE:
        _catalog = {}
    else:
        _catalog = importlib.import_module(f".i18n_{code}", __package__).CATALOG
    _current = code
    return code


def language() -> str:
    return _current


def pref_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "dpigec", "ui.json")


def saved_language() -> Optional[str]:
    try:
        with open(pref_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return normalize_language(data.get("lang")) if isinstance(data, dict) else None


def save_language(code: str) -> bool:
    code = normalize_language(code)
    if code is None:
        return False
    path = pref_path()
    try:
        d = os.path.dirname(path)
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".ui-", dir=d)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"lang": code}, fh)
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def init() -> str:
    """Environment override, then the saved choice, then English."""
    code = normalize_language(os.environ.get("DPIGEC_LANG")) or saved_language()
    return set_language(code)


def _(msg: str, /, **kw: object) -> str:
    # "/": yer tutucu adı "msg" olabilir (ör. "certificate: {msg}"); parametreyle çakışmasın.
    out = _catalog.get(msg, msg)
    return out.format(**kw) if kw else out
