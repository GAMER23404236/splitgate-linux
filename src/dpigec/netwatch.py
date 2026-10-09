# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Varsayılan ağı (arayüz + ağ geçidi) izler; değişince haber verir."""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from typing import Optional

ROUTE_FILE = "/proc/net/route"
ARP_FILE = "/proc/net/arp"


@dataclass(frozen=True)
class NetId:
    key: str      # "wifi:wlan0:192.168.1.1" (arayüz + ağ geçidi)
    label: str    # gösterim, ör. "Wi-Fi (wlan0)"
    mac: str = ""  # ağ geçidinin MAC adresi (biliniyorsa); aynı IP'li farklı ağları ayırır

    @property
    def save_key(self) -> str:
        return self.key + (":" + self.mac if self.mac else "")


def same(a: Optional["NetId"], b: Optional["NetId"]) -> bool:
    """Aynı ağ mı? MAC yalnızca ikisi de biliniyorsa karşılaştırılır (ARP kaydı geç gelebilir)."""
    if a is None or b is None:
        return a is b
    if a.key != b.key:
        return False
    return not (a.mac and b.mac and a.mac != b.mac)


def gateway_mac(gw: str, arp_file: str = ARP_FILE) -> str:
    try:
        with open(arp_file, "r", encoding="ascii") as fh:
            for line in fh.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == gw and parts[3] != "00:00:00:00:00:00":
                    return parts[3].lower()
    except OSError:
        pass
    return ""


def _kind(iface: str, sys_net: str = "/sys/class/net") -> str:
    if os.path.isdir(os.path.join(sys_net, iface, "wireless")):
        return "wifi"
    if iface.startswith(("usb", "rndis", "enx")):
        return "usb"
    if iface.startswith(("wwan", "ppp")):
        return "mobile"
    return "eth"


_LABELS = {"wifi": "Wi-Fi", "usb": "USB tethering", "mobile": "Mobile", "eth": "Ethernet"}


def parse_default_route(text: str):
    """/proc/net/route içeriğinden en düşük metrikli varsayılan rota: (arayüz, ağ geçidi) ya da None."""
    best = None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gw, flags, metric, mask = parts[0], parts[1], parts[2], parts[3], parts[6], parts[7]
        try:
            if int(dest, 16) != 0 or int(mask, 16) != 0 or not int(flags, 16) & 0x1:
                continue
            gw_ip = socket.inet_ntoa(struct.pack("<I", int(gw, 16)))
            m = int(metric)
        except ValueError:
            continue
        if best is None or m < best[2]:
            best = (iface, gw_ip, m)
    return (best[0], best[1]) if best else None


def current(route_file: str = ROUTE_FILE, sys_net: str = "/sys/class/net",
            arp_file: str = ARP_FILE) -> Optional[NetId]:
    try:
        with open(route_file, "r", encoding="ascii") as fh:
            r = parse_default_route(fh.read())
    except OSError:
        return None
    if r is None:
        return None
    iface, gw = r
    kind = _kind(iface, sys_net)
    return NetId(f"{kind}:{iface}:{gw}", f"{_LABELS[kind]} ({iface})", gateway_mac(gw, arp_file))
