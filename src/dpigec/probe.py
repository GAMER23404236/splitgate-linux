"""Strateji sınaması: her ön ayarı gerçek TLS el sıkışmasıyla dener.

Sınama, ClientHello'yu ssl.MemoryBIO ile üretip stratejiye göre parçalayarak
kendi soketinden gönderir. Bağlantılar SO_MARK ile işaretlenir; dolayısıyla
motor çalışırken de sistem yönlendirmesinden etkilenmez. Ad çözümleme DoH
iledir (DNS zehirlenmesi sonucu etkilemez).
"""
from __future__ import annotations

import asyncio
import errno
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from .config import PRESETS
from .i18n import _
from .doh import DohClient, DohResolver, providers_from_config
from .sockutil import make_marked_socket, set_ttl
from .stats import Stats
from .strategy import plan_segments
from .tlsparse import parse_client_hello

PROBE_TIMEOUT = 6.0

# Alan adı sonucundaki makine-okunur hata kodları ("code"); arayüz bunları yerelleştirir.
ERR_DNS = "dns"
ERR_CONNECT_TIMEOUT = "connect-timeout"   # TCP bile kurulamadı: genelde IP engeli
ERR_TIMEOUT = "timeout"                   # bağlandı ama el sıkışma bitmedi
ERR_RESET = "reset"
ERR_REFUSED = "refused"
ERR_UNREACHABLE = "unreachable"
ERR_CLOSED = "closed"
ERR_CERT = "certificate"
ERR_OTHER = "other"

# Teşhis
WORKS = "works"                  # en az bir yöntem engelli bir siteyi açtı
NOT_BLOCKED = "not_blocked"      # siteler bölmeden de açılıyor
DNS_FAILED = "dns_failed"        # DoH'a ulaşılamadı, siteler denenemedi
NO_CONNECTION = "no_connection"  # ağ / yol yok
IP_BLOCK = "ip_block"            # TCP bile kurulmuyor; bölme aşamaz
INTERCEPTED = "intercepted"      # yanlış sertifika: araya giren var
DPI_UNBEATEN = "dpi_unbeaten"    # bağlantı kuruluyor ama DPI her yöntemi yakalıyor


class _ConnectTimeout(Exception):
    pass


async def tls_probe(ip: str, host: str, positions: List[str], delay: float, oob: bool,
                    mark: int, timeout: float = PROBE_TIMEOUT,
                    ctx: Optional[ssl.SSLContext] = None, port: int = 443,
                    tlsrec: bool = False, disorder: bool = False) -> float:
    """Başarılıysa el sıkışma süresini (sn) döndürür; değilse istisna fırlatır."""
    loop = asyncio.get_running_loop()
    ctx = ctx or ssl.create_default_context()
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=host)
    sock = make_marked_socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, mark)
    t0 = time.monotonic()
    try:
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        except asyncio.TimeoutError:
            raise _ConnectTimeout() from None
        first = True
        while True:
            try:
                obj.do_handshake()
                return time.monotonic() - t0
            except ssl.SSLWantReadError:
                pass
            out = outb.read()
            if out:
                if first:
                    first = False
                    target = parse_client_hello(out)
                    segs, _how = plan_segments(out, target, "tls", positions, tlsrec)
                    for i, seg in enumerate(segs):
                        lowered = i == 0 and disorder and len(segs) > 1 and set_ttl(sock, 1)
                        try:
                            await loop.sock_sendall(sock, seg)
                        finally:
                            if lowered and not set_ttl(sock, -1):
                                raise OSError("could not restore TTL")
                        if i == 0 and oob and len(segs) > 1:
                            try:
                                sock.send(b"\x00", socket.MSG_OOB)
                            except OSError:
                                pass
                        if i < len(segs) - 1:
                            await asyncio.sleep(delay)
                else:
                    await loop.sock_sendall(sock, out)
            data = await asyncio.wait_for(loop.sock_recv(sock, 65536), timeout)
            if not data:
                raise ConnectionError("connection closed (EOF)")
            inb.write(data)
    finally:
        sock.close()


def classify(exc: BaseException) -> str:
    if isinstance(exc, _ConnectTimeout):
        return ERR_CONNECT_TIMEOUT
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ERR_CERT
    if isinstance(exc, ConnectionResetError) or isinstance(exc, BrokenPipeError):
        return ERR_RESET
    if isinstance(exc, ConnectionRefusedError):
        return ERR_REFUSED
    err = getattr(exc, "errno", None)
    if err in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return ERR_UNREACHABLE
    if err == errno.ECONNRESET:
        return ERR_RESET
    if isinstance(exc, (ConnectionError, ssl.SSLEOFError, ssl.SSLZeroReturnError)) or "EOF" in str(exc):
        return ERR_CLOSED
    return ERR_OTHER


async def _resolve(resolver, host: str):
    """(ip, None) ya da (None, DNS hata sonucu)."""
    try:
        ips = await resolver.resolve(host)
    except Exception as e:  # noqa: BLE001
        return None, {"ok": False, "code": ERR_DNS, "err": _("DNS: {msg}", msg=f"{type(e).__name__}: {e}"[:60])}
    if not ips:
        return None, {"ok": False, "code": ERR_DNS, "err": _("DNS: no address")}
    return ([i for i in ips if ":" not in i] or ips)[0], None


async def _probe_one(ip: Optional[str], dns_err, host: str, st: Dict[str, Any], mark) -> Dict[str, Any]:
    if ip is None:
        return dns_err
    ips = [ip]
    try:
        elapsed = await tls_probe(ips[0], host, st["positions"], st["delay_ms"] / 1000.0, st["oob"], mark,
                                  tlsrec=st.get("tlsrec", False), disorder=st.get("disorder", False))
        return {"ok": True, "ms": int(elapsed * 1000)}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "code": ERR_CERT, "err": _("certificate: {msg}", msg=e.verify_message)}
    except _ConnectTimeout:
        return {"ok": False, "code": ERR_CONNECT_TIMEOUT, "err": _("could not connect (timed out)")}
    except asyncio.TimeoutError:
        return {"ok": False, "code": ERR_TIMEOUT, "err": _("timed out")}
    except (OSError, ssl.SSLError, ConnectionError) as e:
        return {"ok": False, "code": classify(e), "err": f"{type(e).__name__}: {e}"[:80]}


BASELINE = {"positions": [], "delay_ms": 0, "oob": False, "tlsrec": False, "disorder": False}


def plans_for(keys: Optional[List[str]] = None):
    """(anahtar, etiket, strateji) listesi; "none" bölmesiz taban çizgisidir ve her zaman ilk sıradadır."""
    out = [("none", "No splitting (baseline)", BASELINE)]
    for key, p in PRESETS.items():
        if keys is None or key in keys:
            out.append((key, p["label"], p))
    return out


async def run_probe(cfg: Dict[str, Any], domains: Optional[List[str]] = None,
                    progress=None, presets: Optional[List[Tuple[str, str, Dict[str, Any]]]] = None
                    ) -> List[Dict[str, Any]]:
    domains = domains or cfg["probe_domains"]
    stats = Stats()
    client = DohClient(providers_from_config(cfg["dns"]), cfg["fwmark"], cfg["dns"]["timeout"],
                       cfg["ipv6"], stats)
    resolver = DohResolver(client, False, 120)
    mark = cfg["fwmark"]
    plans = presets if presets is not None else plans_for()
    results: List[Dict[str, Any]] = []
    try:
        # Her site bir kez çözülür: DoH engelliyse her turda yeniden beklenmez ve tüm yöntemler aynı IP'yi dener.
        resolved = await asyncio.gather(*(_resolve(resolver, d) for d in domains))
        for key, label, st in plans:
            if progress:
                progress(key, label)
            res = await asyncio.gather(*(_probe_one(ip, err, d, st, mark)
                                         for d, (ip, err) in zip(domains, resolved)))
            per = dict(zip(domains, res))
            oks = [r for r in res if r["ok"]]
            results.append({
                "preset": key,
                "label": label,
                "ok": len(oks),
                "total": len(domains),
                "avg_ms": int(sum(r["ms"] for r in oks) / len(oks)) if oks else None,
                "domains": per,
            })
    finally:
        client.close()
    return results


def find(results: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
    for r in results:
        if r["preset"] == key:
            return r
    return None


def reachable(r: Dict[str, Any]) -> int:
    """DNS'i çözülebilen (gerçekten denenebilen) site sayısı."""
    return sum(1 for d in r["domains"].values() if d["ok"] or d.get("code") != ERR_DNS)


def not_blocked(results: List[Dict[str, Any]]) -> bool:
    base = find(results, "none")
    return base is not None and reachable(base) > 0 and base["ok"] == reachable(base)


def bypasses(results: List[Dict[str, Any]], r: Optional[Dict[str, Any]]) -> bool:
    """Yöntem, bölmesiz bağlantının açamadığı en az bir siteyi açıyor mu."""
    if r is None or r["preset"] == "none" or r["ok"] == 0:
        return False
    base = find(results, "none")
    if base is None:
        return True
    for name, d in r["domains"].items():
        b = base["domains"].get(name)
        if d["ok"] and b is not None and not b["ok"] and b.get("code") != ERR_DNS:
            return True
    return False


def best_preset(results: List[Dict[str, Any]]) -> Optional[str]:
    """Engelli siteleri en çok açan (eşitlikte en hızlı) ön ayar; hiçbiri aşamıyorsa None."""
    cands = [r for r in results if bypasses(results, r)]
    if not cands:
        return None
    cands.sort(key=lambda r: (-r["ok"], r["avg_ms"] if r["avg_ms"] is not None else 10 ** 9))
    return cands[0]["preset"]


def verdict_text(v: str) -> str:
    return {
        WORKS: _("A method works here: apply the recommended one."),
        NOT_BLOCKED: _("The test sites open without splitting: they are not blocked on this network. "
                       "Put sites that are blocked for you in the list."),
        DNS_FAILED: _("Encrypted DNS (DoH) cannot be reached, so the sites could not be tried. Pick another "
                      "DNS provider or check your internet connection."),
        NO_CONNECTION: _("No internet connection on this network."),
        IP_BLOCK: _("Even a plain connection to the sites is not possible: this looks like an IP block. "
                    "Splitting cannot get around it; only a real VPN or proxy can."),
        INTERCEPTED: _("The sites answer with a wrong certificate: something on this network (operator, modem "
                       "or school/company filter) intercepts the connection. Splitting cannot get around it."),
    }.get(v, _("The connection is made but the filter catches every method on this network. "
               "Send a report so it can be looked at."))


def diagnose(results: List[Dict[str, Any]]) -> str:
    cells = [d for r in results for d in r["domains"].values()]
    if not cells or all((not d["ok"]) and d.get("code") == ERR_DNS for d in cells):
        return DNS_FAILED
    if not_blocked(results):
        return NOT_BLOCKED
    if any(bypasses(results, r) for r in results):
        return WORKS
    connect = unreachable = cert = other = 0
    for d in cells:
        if d["ok"] or d.get("code") == ERR_DNS:
            continue
        code = d.get("code")
        if code in (ERR_CONNECT_TIMEOUT, ERR_REFUSED):
            connect += 1
        elif code == ERR_UNREACHABLE:
            unreachable += 1
        elif code == ERR_CERT:
            cert += 1
        else:
            other += 1
    # Eşitlikte DPI_UNBEATEN: yanlışlıkla "yalnızca VPN aşar" denmesin.
    if unreachable > max(connect, cert, other):
        return NO_CONNECTION
    if connect > max(unreachable, cert, other):
        return IP_BLOCK
    if cert > max(unreachable, connect, other):
        return INTERCEPTED
    return DPI_UNBEATEN
