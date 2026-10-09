"""Yapılandırma: varsayılanlar, doğrulama, yükleme / kaydetme.

Yapılandırma dosyası root tarafından uygulanır; bu yüzden her alan sıkı
doğrulanır ve nftables kural metnine yalnızca doğrulanmış sayılar girer.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import tempfile
from typing import Any, Dict, Optional

from .i18n import _

SYSTEM_CONFIG = "/etc/dpigec/config.json"
RUN_DIR = "/run/dpigec"
STATUS_FILE = RUN_DIR + "/status.json"
LOG_FILE = RUN_DIR + "/dpigec.log"


class ConfigError(ValueError):
    """Geçersiz yapılandırma."""


# Konum belirteçleri:
#   N        payload başından N bayt sonra
#   method   HTTP metodundan hemen sonra
#   host/sni ana makine adının başlangıcı (HTTP Host değeri veya TLS SNI)
#   hostmid  ana makine adının ortası
#   midsld   ikinci seviye alan adının (ör. "discord") ortası
#   sniend   ana makine adının bitişi
#   sniext   TLS server_name uzantısının başlangıcı
POS_RE = re.compile(r"^(\d{1,4}|method|host|sni|hostmid|midsld|sniend|sniext)$")
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOST_RE = re.compile(r"^(?=.{1,253}$)" + _LABEL + r"(?:\." + _LABEL + r")*$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$")

PRESETS: Dict[str, Dict[str, Any]] = {
    "hafif": {
        "label": "Light (single split)",
        "positions": ["midsld"],
        "delay_ms": 0,
        "oob": False,
    },
    "sni": {
        "label": "Split at SNI start",
        "positions": ["1", "sni"],
        "delay_ms": 1,
        "oob": False,
    },
    "agresif": {
        "label": "Aggressive (many pieces)",
        "positions": ["1", "3", "sni", "midsld", "sniend"],
        "delay_ms": 3,
        "oob": False,
    },
    "oob": {
        "label": "OOB byte (experimental)",
        "positions": ["1", "midsld"],
        "delay_ms": 2,
        "oob": True,
    },
    "tlskayit": {
        "label": "TLS + TCP split",
        "positions": ["hostmid"],
        "delay_ms": 3,
        "oob": False,
        "tlsrec": True,
    },
    "disorder": {
        "label": "Disorder",
        "positions": ["1"],
        "delay_ms": 0,
        "oob": False,
        "disorder": True,
    },
    "disordersni": {
        "label": "Disorder (site name)",
        "positions": ["midsld"],
        "delay_ms": 0,
        "oob": False,
        "disorder": True,
    },
    "tlsdisorder": {
        "label": "TLS + disorder",
        "positions": ["hostmid"],
        "delay_ms": 0,
        "oob": False,
        "tlsrec": True,
        "disorder": True,
    },
}
for _p in PRESETS.values():
    _p.setdefault("tlsrec", False)
    _p.setdefault("disorder", False)

DEFAULTS: Dict[str, Any] = {
    "version": 1,
    # "transparent": sistem geneli (root, nftables) | "socks": yerel SOCKS5/HTTP vekil
    "mode": "transparent",
    "listen_port": 18443,
    "dns_port": 15353,
    "socks_port": 1080,
    "fwmark": 17488,  # 0x4450 - motorun kendi bağlantılarını yönlendirmeden hariç tutar
    "gateway": False,  # True: bu makineden geçen (yönlendirilen) trafiği de işle
    "ipv6": True,
    "strategy": {
        "preset": "sni",  # PRESETS anahtarlarindan biri ya da custom
        "positions": ["1", "midsld"],  # yalnızca preset=custom iken kullanılır
        "delay_ms": 1,
        "oob": False,
        "tlsrec": False,  # ClientHello'yu ilk konumdan iki TLS kaydina bol
        "disorder": False,  # ilk parcayi TTL 1 ile gonder (sunucuya sirasiz ulasir)
        "http_host_case": False,  # "Host:" -> "hOsT:"
        "http_split": True,
    },
    "dns": {
        "enabled": True,
        "providers": ["cloudflare", "google", "quad9"],
        "custom": {"host": "", "ips": [], "path": "/dns-query"},
        "cache_seconds": 300,
        "timeout": 5,
    },
    "ports": [80, 443],
    "quic_block": True,  # UDP/443'ü reddet; tarayıcılar TCP'ye döner
    "domain_filter": {"mode": "all", "domains": []},  # all | include | exclude
    "probe_domains": ["discord.com", "x.com", "roblox.com", "wattpad.com"],
    # Seçili yöntem bu ağda engelli test sitelerini açmıyorsa diğerlerini dene, çalışanı kullan ve ağ için hatırla
    "auto_method": True,
    "log_domains": False,
    "log_level": "info",
}


def default_config() -> Dict[str, Any]:
    return copy.deepcopy(DEFAULTS)


def effective_strategy(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Preset'i çözümleyip kullanılacak bölme parametrelerini döndürür."""
    st = cfg["strategy"]
    out = {
        "http_host_case": st["http_host_case"],
        "http_split": st["http_split"],
    }
    preset = st["preset"]
    if preset == "custom":
        out.update(positions=list(st["positions"]), delay_ms=st["delay_ms"], oob=st["oob"],
                   tlsrec=st["tlsrec"], disorder=st["disorder"])
    else:
        p = PRESETS[preset]
        out.update(positions=list(p["positions"]), delay_ms=p["delay_ms"], oob=p["oob"],
                   tlsrec=p["tlsrec"], disorder=p["disorder"])
    return out


# --------------------------------------------------------------------------
# Doğrulama
# --------------------------------------------------------------------------

def _merge(base: Dict[str, Any], user: Dict[str, Any]) -> None:
    for key, val in user.items():
        if key not in base:
            continue  # bilinmeyen anahtarlar yok sayılır
        if isinstance(base[key], dict) and isinstance(val, dict):
            _merge(base[key], val)
        else:
            base[key] = val


def _int(name: str, v: Any, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ConfigError(_("{name}: must be an integer between {lo} and {hi}", name=name, lo=lo, hi=hi))
    return v


def _bool(name: str, v: Any) -> bool:
    if not isinstance(v, bool):
        raise ConfigError(_("{name}: must be true/false", name=name))
    return v


def _enum(name: str, v: Any, allowed) -> str:
    if v not in allowed:
        raise ConfigError(_("{name}: must be one of: {allowed}", name=name, allowed=", ".join(allowed)))
    return v


def _domain_list(name: str, v: Any, limit: int = 2000) -> list:
    if not isinstance(v, list) or len(v) > limit:
        raise ConfigError(_("{name}: must be a list (at most {limit})", name=name, limit=limit))
    out = []
    for item in v:
        if not isinstance(item, str):
            raise ConfigError(_("{name}: domain name must be text", name=name))
        d = item.strip().lower().lstrip("*.").rstrip(".")
        if not d:
            continue
        if not HOST_RE.match(d):
            raise ConfigError(_("{name}: invalid domain name: {item}", name=name, item=repr(item)))
        if d not in out:
            out.append(d)
    return out


def validate(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """cfg'yi yerinde doğrular/normalleştirir ve döndürür."""
    cfg["version"] = 1
    _enum("mode", cfg["mode"], ("transparent", "socks"))
    _int("listen_port", cfg["listen_port"], 1024, 65535)
    _int("dns_port", cfg["dns_port"], 1024, 65535)
    _int("socks_port", cfg["socks_port"], 1024, 65535)
    _int("fwmark", cfg["fwmark"], 1, 0x7FFFFFFF)
    _bool("gateway", cfg["gateway"])
    _bool("ipv6", cfg["ipv6"])
    _bool("quic_block", cfg["quic_block"])
    _bool("auto_method", cfg["auto_method"])
    _bool("log_domains", cfg["log_domains"])
    _enum("log_level", cfg["log_level"], ("debug", "info", "warning", "error"))
    ports = {cfg["listen_port"], cfg["dns_port"], cfg["socks_port"]}
    if len(ports) != 3:
        raise ConfigError(_("listen_port, dns_port and socks_port must be different from each other"))

    st = cfg["strategy"]
    _enum("strategy.preset", st["preset"], tuple(PRESETS) + ("custom",))
    pos = st["positions"]
    if not isinstance(pos, list) or not 1 <= len(pos) <= 12:
        raise ConfigError(_("strategy.positions: must be a list of 1-12 items"))
    norm = []
    for p in pos:
        p = str(p).strip().lower()
        if not POS_RE.match(p):
            raise ConfigError(_("strategy.positions: invalid position {p}", p=repr(p)))
        if p not in norm:
            norm.append(p)
    st["positions"] = norm
    _int("strategy.delay_ms", st["delay_ms"], 0, 200)
    _bool("strategy.oob", st["oob"])
    _bool("strategy.tlsrec", st["tlsrec"])
    _bool("strategy.disorder", st["disorder"])
    _bool("strategy.http_host_case", st["http_host_case"])
    _bool("strategy.http_split", st["http_split"])

    dns = cfg["dns"]
    _bool("dns.enabled", dns["enabled"])
    provs = dns["providers"]
    if not isinstance(provs, list) or not 1 <= len(provs) <= 5:
        raise ConfigError(_("dns.providers: must be a list of 1-5 items"))
    for p in provs:
        _enum("dns.providers", p, ("cloudflare", "google", "quad9", "custom"))
    dns["providers"] = list(dict.fromkeys(provs))
    custom = dns["custom"]
    if not isinstance(custom["host"], str) or (custom["host"] and not HOST_RE.match(custom["host"])):
        raise ConfigError(_("dns.custom.host is invalid"))
    if not isinstance(custom["ips"], list) or len(custom["ips"]) > 6:
        raise ConfigError(_("dns.custom.ips: at most 6 IPs"))
    try:
        custom["ips"] = [str(ipaddress.ip_address(i)) for i in custom["ips"]]
    except ValueError as e:
        raise ConfigError(f"dns.custom.ips: {e}")
    if not isinstance(custom["path"], str) or not PATH_RE.match(custom["path"]):
        raise ConfigError(_("dns.custom.path is invalid"))
    if "custom" in dns["providers"] and not (custom["host"] and custom["ips"]):
        raise ConfigError(_("host and ips are required for a custom DoH provider"))
    _int("dns.cache_seconds", dns["cache_seconds"], 0, 86400)
    _int("dns.timeout", dns["timeout"], 1, 30)

    pl = cfg["ports"]
    if not isinstance(pl, list) or not 1 <= len(pl) <= 16:
        raise ConfigError(_("ports: must be a list of 1-16 items"))
    cfg["ports"] = sorted({_int("ports", p, 1, 65535) for p in pl})

    df = cfg["domain_filter"]
    _enum("domain_filter.mode", df["mode"], ("all", "include", "exclude"))
    df["domains"] = _domain_list("domain_filter.domains", df["domains"])
    cfg["probe_domains"] = _domain_list("probe_domains", cfg["probe_domains"], 20)
    return cfg


def normalize(user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = default_config()
    if user is not None:
        if not isinstance(user, dict):
            raise ConfigError(_("the configuration must be a JSON object"))
        strategy = user.get("strategy")
        if isinstance(strategy, dict) and strategy.get("preset") == "turkiye":
            user = {**user, "strategy": {**strategy, "preset": "sni"}}
        _merge(cfg, user)
    try:
        return validate(cfg)
    except (KeyError, TypeError) as e:
        raise ConfigError(_("malformed configuration structure: {e}", e=e))


# --------------------------------------------------------------------------
# Dosya işlemleri
# --------------------------------------------------------------------------

def default_config_path() -> str:
    if os.geteuid() == 0:
        return SYSTEM_CONFIG
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "dpigec", "config.json")


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or default_config_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return normalize(None)
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(_("could not read {path}: {e}", path=path, e=e))
    return normalize(raw)


def save_config(cfg: Dict[str, Any], path: Optional[str] = None) -> str:
    path = path or default_config_path()
    cfg = normalize(cfg)
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cfg-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path
