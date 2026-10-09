"""DNS-over-HTTPS istemcisi ve ad çözücü.

Sağlayıcılara doğrudan IP ile bağlanılır (önyükleme için DNS gerekmez).
Bağlantılar SO_MARK ile işaretlenir; böylece nftables yönlendirmesine
takılmaz. Yalnızca standart kütüphane kullanılır.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import dnswire
from .sockutil import is_ip, make_marked_socket
from .stats import Stats

log = logging.getLogger("dpigec.doh")

CONNECT_TIMEOUT = 4.0


@dataclass
class Provider:
    name: str
    host: str
    ips: List[str]
    path: str = "/dns-query"
    port: int = 443
    down_until: float = 0.0


BUILTIN = {
    "cloudflare": ("cloudflare-dns.com", ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"]),
    "google": ("dns.google", ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"]),
    "quad9": ("dns.quad9.net", ["9.9.9.9", "149.112.112.112", "2620:fe::fe"]),
}


def providers_from_config(dns_cfg: dict) -> List[Provider]:
    out = []
    for name in dns_cfg["providers"]:
        if name == "custom":
            c = dns_cfg["custom"]
            out.append(Provider("custom", c["host"], list(c["ips"]), c["path"]))
        else:
            host, ips = BUILTIN[name]
            out.append(Provider(name, host, list(ips)))
    return out


class DohError(Exception):
    pass


class DohClient:
    def __init__(self, providers: List[Provider], mark: int, timeout: float = 5.0,
                 ipv6: bool = True, stats: Optional[Stats] = None,
                 ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self.providers = providers
        self.mark = mark
        self.timeout = timeout
        self.ipv6 = ipv6
        self.stats = stats or Stats()
        self.ctx = ssl_context or ssl.create_default_context()
        self._idle: Dict[tuple, list] = {}

    # ---- bağlantı yönetimi -------------------------------------------------
    async def _open(self, prov: Provider, ip: str):
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = make_marked_socket(fam, self.mark)
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, prov.port)), CONNECT_TIMEOUT)
            return await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=self.ctx, server_hostname=prov.host),
                self.timeout)
        except BaseException:
            sock.close()
            raise

    async def _exchange(self, prov: Provider, ip: str, wire: bytes) -> bytes:
        key = (prov.host, ip, prov.port)
        pool = self._idle.setdefault(key, [])
        # Önce boşta bekleyen bağlantıyı dene; bayatsa yenisini aç.
        while True:
            reused = bool(pool)
            if reused:
                reader, writer = pool.pop()
            else:
                reader, writer = await self._open(prov, ip)
            try:
                body, keep = await asyncio.wait_for(self._request(prov, reader, writer, wire),
                                                    self.timeout)
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, OSError):
                writer.close()
                if reused:
                    continue
                raise
            except BaseException:
                writer.close()
                raise
            if keep and len(pool) < 4:
                pool.append((reader, writer))
            else:
                writer.close()
            return body

    @staticmethod
    async def _request(prov: Provider, reader, writer, wire: bytes):
        head = (f"POST {prov.path} HTTP/1.1\r\nHost: {prov.host}\r\n"
                "Content-Type: application/dns-message\r\n"
                "Accept: application/dns-message\r\n"
                f"Content-Length: {len(wire)}\r\nConnection: keep-alive\r\n\r\n").encode("ascii")
        writer.write(head + wire)
        await writer.drain()
        raw = await reader.readuntil(b"\r\n\r\n")
        lines = raw.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or parts[1] != "200":
            raise DohError(f"HTTP {lines[0][:40]}")
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip().lower()
        keep = hdrs.get("connection", "keep-alive") != "close"
        if hdrs.get("transfer-encoding") == "chunked":
            body = b""
            while True:
                size = int((await reader.readuntil(b"\r\n")).strip().split(b";")[0], 16)
                if size == 0:
                    await reader.readuntil(b"\r\n")
                    break
                body += await reader.readexactly(size)
                await reader.readexactly(2)
        elif "content-length" in hdrs:
            n = int(hdrs["content-length"])
            if n > 65535:
                raise DohError("response too large")
            body = await reader.readexactly(n)
        else:
            body = await reader.read(65535)
            keep = False
        return body, keep

    # ---- genel arayüz ------------------------------------------------------
    async def query(self, wire: bytes) -> bytes:
        """DNS sorgusunu (tel biçimi) DoH ile çözer; hata durumunda DohError."""
        now = time.monotonic()
        order = [p for p in self.providers if p.down_until <= now] or list(self.providers)
        last: Optional[BaseException] = None
        for prov in order:
            for ip in prov.ips:
                if ":" in ip and not self.ipv6:
                    continue
                try:
                    body = await self._exchange(prov, ip, wire)
                    if len(body) < 12:
                        raise DohError("short response")
                    prov.down_until = 0.0
                    self.stats.doh_ok += 1
                    return body
                except (asyncio.TimeoutError, OSError, ssl.SSLError, DohError,
                        asyncio.IncompleteReadError, ValueError) as e:
                    last = e
                    log.debug("DoH error %s/%s: %r", prov.name, ip, e)
            prov.down_until = time.monotonic() + 30
            self.stats.doh_fail += 1
        raise DohError(f"all DoH providers failed: {last!r}")

    def health(self) -> List[dict]:
        now = time.monotonic()
        return [{"name": p.name, "ok": p.down_until <= now} for p in self.providers]

    def close(self) -> None:
        for pool in self._idle.values():
            for _r, w in pool:
                w.close()
        self._idle.clear()


@dataclass
class _Entry:
    expires: float
    addrs: List[str] = field(default_factory=list)


class DohResolver:
    """Alan adı -> IP çözücü (SOCKS modu ve sınama için), DoH tabanlı."""

    def __init__(self, client: DohClient, ipv6: bool = True, cache_seconds: int = 300) -> None:
        self.client = client
        self.ipv6 = ipv6
        self.cache_seconds = cache_seconds
        self._cache: Dict[str, _Entry] = {}

    def flush(self) -> None:
        self._cache.clear()

    async def _lookup(self, host: str, qtype: int) -> _Entry:
        resp = await self.client.query(dnswire.build_query(host, qtype))
        rcode, addrs, ttl = dnswire.parse_answers(resp)
        if rcode not in (0, 3):
            raise DohError(f"DNS rcode={rcode}")
        return _Entry(time.monotonic() + min(max(ttl, 30), self.cache_seconds or 30), addrs)

    async def resolve(self, host: str) -> List[str]:
        if is_ip(host):
            return [host]
        host = host.lower().rstrip(".")
        hit = self._cache.get(host)
        if hit and hit.expires > time.monotonic():
            return list(hit.addrs)
        qtypes = [dnswire.QTYPE_A] + ([dnswire.QTYPE_AAAA] if self.ipv6 else [])
        results = await asyncio.gather(*(self._lookup(host, q) for q in qtypes),
                                       return_exceptions=True)
        addrs: List[str] = []
        expires = None
        errors = []
        for r in results:
            if isinstance(r, Exception):
                errors.append(r)
            else:
                addrs += r.addrs
                expires = r.expires if expires is None else min(expires, r.expires)
        if not addrs:
            raise OSError(f"{host} could not be resolved: {errors[0] if errors else 'no record'}")
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[host] = _Entry(expires or time.monotonic() + 30, addrs)
        return addrs


class SystemResolver:
    """DoH kapalıyken sistem çözücüsünü kullanan basit sarmalayıcı."""

    def __init__(self, ipv6: bool = True) -> None:
        self.ipv6 = ipv6

    async def resolve(self, host: str) -> List[str]:
        if is_ip(host):
            return [host]
        loop = asyncio.get_running_loop()
        fam = socket.AF_UNSPEC if self.ipv6 else socket.AF_INET
        infos = await loop.getaddrinfo(host, None, family=fam, type=socket.SOCK_STREAM)
        out: List[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
        return out
