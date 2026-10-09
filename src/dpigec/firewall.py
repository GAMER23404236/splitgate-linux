"""nftables kuralları: 80/443 TCP ve 53 DNS trafiğini yerel vekile yönlendirir."""
from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any, Dict

from .i18n import _

log = logging.getLogger("dpigec.fw")

TABLE = "dpigec"
PRIV4 = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10"
PRIV6 = "::1, fc00::/7, fe80::/10"


class FirewallError(RuntimeError):
    pass


def render_ruleset(cfg: Dict[str, Any]) -> str:
    """Doğrulanmış yapılandırmadan nft betiği üretir (yalnızca sayılar girer)."""
    mark = int(cfg["fwmark"])
    lport = int(cfg["listen_port"])
    dport = int(cfg["dns_port"])
    ports = ", ".join(str(int(p)) for p in cfg["ports"])
    dns_on = bool(cfg["dns"]["enabled"])
    gateway = bool(cfg["gateway"])

    def nat_rules(local_skip: str) -> str:
        lines = [local_skip]
        if dns_on:
            lines += [
                f"udp dport 53 redirect to :{dport}",
                f"tcp dport 53 redirect to :{dport}",
            ]
        lines += [
            f"ip daddr {{ {PRIV4} }} return",
            f"ip6 daddr {{ {PRIV6} }} return",
            f"tcp dport {{ {ports} }} redirect to :{lport}",
        ]
        return "\n\t\t".join(lines)

    out = [
        f"add table inet {TABLE}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
        "\tchain nat_output {",
        "\t\ttype nat hook output priority -100; policy accept;",
        f"\t\tmeta mark {mark} return",
        "\t\t" + nat_rules('oifname "lo" return'),
        "\t}",
    ]
    if gateway:
        out += [
            "\tchain nat_prerouting {",
            "\t\ttype nat hook prerouting priority -100; policy accept;",
            "\t\t" + nat_rules('fib daddr type local return'),
            "\t}",
        ]
    if cfg["quic_block"] and 443 in cfg["ports"]:
        out += [
            "\tchain quic_output {",
            "\t\ttype filter hook output priority 0; policy accept;",
            f"\t\tmeta mark {mark} return",
            '\t\toifname "lo" return',
            "\t\tudp dport 443 reject",
            "\t}",
        ]
        if gateway:
            out += [
                "\tchain quic_forward {",
                "\t\ttype filter hook forward priority 0; policy accept;",
                "\t\tudp dport 443 reject",
                "\t}",
            ]
    out.append("}")
    return "\n".join(out) + "\n"


def _nft() -> str:
    path = shutil.which("nft")
    if not path:
        raise FirewallError(_("nft not found: install the 'nftables' package"))
    return path


def apply(cfg: Dict[str, Any], check_only: bool = False) -> None:
    script = render_ruleset(cfg)
    cmd = [_nft()] + (["-c"] if check_only else []) + ["-f", "-"]
    res = subprocess.run(cmd, input=script, text=True, capture_output=True, timeout=20)
    if res.returncode != 0:
        raise FirewallError(_("nft error: {out}", out=res.stderr.strip() or res.stdout.strip()))
    if not check_only:
        log.info("nftables rules applied")


def remove() -> bool:
    """Tablo varsa siler; yoksa sessizce geçer. Silindiyse True döndürür."""
    try:
        res = subprocess.run([_nft(), "delete", "table", "inet", TABLE],
                             capture_output=True, text=True, timeout=20)
    except (FirewallError, subprocess.SubprocessError):
        return False
    if res.returncode == 0:
        log.info("nftables rules removed")
        return True
    return False


def is_installed() -> bool:
    try:
        res = subprocess.run([_nft(), "list", "table", "inet", TABLE],
                             capture_output=True, text=True, timeout=10)
    except (FirewallError, subprocess.SubprocessError):
        return False
    return res.returncode == 0
