# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gerçek kontrol: seçili yöntem bu ağda engelli siteleri gerçekten açıyor mu?

Sonuç "working" yalnızca yöntem, bölmesiz bağlantının açamadığı en az bir siteyi açtıysa olur.
Açmıyorsa (ve otomatik seçim açıksa) önce bu ağ için kayıtlı yöntem, sonra tüm yöntemler denenir;
çalışan uygulanır ve ağ için kaydedilir.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import probe
from .config import PRESETS, effective_strategy
from .netwatch import NetId

log = logging.getLogger("dpigec.check")

STATE_DIR = "/var/lib/dpigec"
NETWORKS_FILE = STATE_DIR + "/networks.json"
MAX_NETWORKS = 256

CHECKING = "checking"
WORKING = "working"
NOT_BLOCKED = "not_blocked"
FAILED = "failed"
IDLE = "idle"

ProbeFn = Callable[..., Awaitable[List[Dict[str, Any]]]]


def load_networks(path: str = NETWORKS_FILE) -> Dict[str, Dict[str, str]]:
    # Bozuk/kötü niyetli dosya servisi çökertmemeli: her hata "kayıt yok" sayılır.
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001  (OSError, ValueError, RecursionError, ...)
        return {}
    out: Dict[str, Dict[str, str]] = {}
    if isinstance(data, dict):
        for k, v in list(data.items())[:MAX_NETWORKS]:
            if not (isinstance(k, str) and len(k) <= 160 and isinstance(v, dict)):
                continue
            preset = v.get("preset")
            if isinstance(preset, str) and preset in PRESETS:
                out[k] = {"preset": preset, "label": str(v.get("label", ""))[:60]}
    return out


def save_networks(nets: Dict[str, Dict[str, str]], path: str = NETWORKS_FILE) -> None:
    d = os.path.dirname(path)
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".net-", dir=d)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(nets, fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("could not save networks: %s", e)


class Checker:
    def __init__(self, cfg: Dict[str, Any], run_probe: ProbeFn = probe.run_probe,
                 networks_path: str = NETWORKS_FILE) -> None:
        self.cfg = cfg
        self.run_probe = run_probe
        self.networks_path = networks_path
        self.networks = load_networks(networks_path)

    def saved_for(self, net: Optional[NetId]) -> Optional[str]:
        if net is None:
            return None
        e = self.networks.get(net.save_key)
        return e["preset"] if e else None

    def _save(self, net: Optional[NetId], preset: str) -> None:
        if net is None:
            return
        self.networks[net.save_key] = {"preset": preset, "label": net.label}
        while len(self.networks) > MAX_NETWORKS:  # dosya sınırsız büyümesin (yüklerken de bu sınır uygulanır)
            self.networks.pop(next(iter(self.networks)))
        save_networks(self.networks, self.networks_path)

    async def _try(self, keys: Optional[List[str]], custom: bool = False) -> List[Dict[str, Any]]:
        plans = probe.plans_for(keys)
        if custom:
            plans.append(("custom", "Custom", effective_strategy(self.cfg)))
        return await self.run_probe(self.cfg, None, None, plans)

    async def verify(self, net: Optional[NetId], active: str, apply: Callable[[str], None],
                     still: Callable[[], bool] = lambda: True) -> Dict[str, Any]:
        """active: şu an kullanılan ön ayar (custom olabilir). apply(preset): yöntemi canlı uygular.

        still(): sonuç uygulanmadan/kaydedilmeden hemen önce hâlâ aynı ağda mıyız. Ağ yoklaması birkaç saniyede
        bir olduğu için, test sürerken ağ değişmiş olabilir; o zaman eski ağa ait olmayan sonuç kaydedilmez.
        """
        custom = active == "custom"
        # Kullanıcının kendi (custom) stratejisi çalışmıyorsa sessizce ön ayara geçilmez; durum bildirilir.
        auto = self.cfg.get("auto_method", True) and not custom
        label = net.label if net else "?"
        keys = [active] if active in PRESETS else []
        results = await self._try(keys, custom)
        cur = probe.find(results, active)
        if probe.bypasses(results, cur):
            return self._result(WORKING, results, active, cur)
        if probe.not_blocked(results):
            return self._result(NOT_BLOCKED, results, active, probe.find(results, "none"))
        if probe.diagnose(results) == probe.DNS_FAILED or not auto:
            return self._result(FAILED, results, active, None)

        saved = self.saved_for(net)
        if saved and saved != active:
            log.info("%s does not open the test sites on %s, trying the saved method", active, label)
            tried = await self._try([saved])
            r = probe.find(tried, saved)
            if probe.bypasses(tried, r) and still():
                apply(saved)
                return self._result(WORKING, tried, saved, r)

        log.info("trying all methods on %s", label)
        full = await self._try(None)
        best = probe.best_preset(full)
        if best is None or not still():
            return self._result(FAILED, full, active, None)
        apply(best)
        self._save(net, best)
        return self._result(WORKING, full, best, probe.find(full, best))

    @staticmethod
    def _result(state: str, results, preset: str, r) -> Dict[str, Any]:
        return {
            "check": state,
            "preset": preset,
            "detail": f"{r['ok']}/{probe.reachable(r)}" if r else "",
            "verdict": probe.diagnose(results),
            "results": results,
        }
