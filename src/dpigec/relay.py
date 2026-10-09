"""Çekirdek aktarıcı: istemci <-> sunucu arasında veriyi taşır, ilk uçuşu böler."""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Awaitable, Callable, Optional

from .config import effective_strategy
from .sockutil import is_ip, make_marked_socket, set_ttl
from .stats import Stats
from .strategy import mix_host_case, plan_segments, should_desync
from .tlsparse import (Target, looks_like_http, looks_like_tls, parse_client_hello,
                       parse_http_request, tls_record_total)

log = logging.getLogger("dpigec.relay")

CONNECT_TIMEOUT = 8.0
CHUNK = 65536

# on_connect(None) -> başarılı, on_connect(exc) -> başarısız (SOCKS yanıtı için)
ConnectCb = Callable[[Optional[BaseException]], Awaitable[None]]


def _close(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass


class Relay:
    def __init__(self, cfg: dict, stats: Stats, resolver) -> None:
        self.cfg = cfg
        self.stats = stats
        self.resolver = resolver
        st = effective_strategy(cfg)
        self.set_strategy(st)
        self._conns: dict = {}
        self.host_case = st["http_host_case"]
        self.http_split = st["http_split"]
        self.filter_mode = cfg["domain_filter"]["mode"]
        self.filter_domains = cfg["domain_filter"]["domains"]
        self.mark = cfg["fwmark"]
        self.ipv6 = cfg["ipv6"]
        self.show_domains = cfg["log_domains"]

    def set_strategy(self, st: dict) -> None:
        """Bölme yöntemini canlı değiştirir; yeni bağlantılar hemen kullanır (tek atamayla, karışmaz)."""
        self._st = (list(st["positions"]), st["delay_ms"] / 1000.0, st["oob"], st["tlsrec"], st["disorder"])

    def reset_connections(self) -> int:
        """Ağ değişince açık bağlantıları kapatır; uygulamalar yeni ağdan hemen yeniden bağlanır."""
        n = 0
        for cw, uw in [tuple(e) for e in list(self._conns.values())]:
            _close(uw)
            transport = cw.transport
            try:
                sock = transport.get_extra_info("socket")
                if sock is not None:
                    # SO_LINGER 0: istemciye RST gider; bağlantının bittiğini beklemeden anlar.
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            transport.abort()
            n += 1
        self._conns.clear()
        return n

    def _label(self, host: str) -> str:
        return host if self.show_domains else "***"

    # ---- yukarı akış bağlantısı -------------------------------------------
    async def open_upstream(self, host: str, port: int):
        ips = [host] if is_ip(host) else await self.resolver.resolve(host)
        if not ips:
            raise OSError("could not be resolved")
        loop = asyncio.get_running_loop()
        last: Optional[BaseException] = None
        for ip in ips[:6]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if fam == socket.AF_INET6 and not self.ipv6:
                continue
            sock = make_marked_socket(fam, self.mark)
            try:
                await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                sock.close()
                last = e
                continue
            reader, writer = await asyncio.open_connection(sock=sock)
            return reader, writer, sock
        raise last or OSError("could not connect")

    # ---- ana giriş ---------------------------------------------------------
    async def serve(self, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter,
                    host: str, port: int, on_connect: Optional[ConnectCb] = None) -> None:
        self.stats.conn_open()
        uwriter = None
        entry = [cwriter, None]
        self._conns[id(cwriter)] = entry  # bağlanmakta olan bağlantılar da ağ değişiminde sıfırlanır
        try:
            try:
                ureader, uwriter, usock = await self.open_upstream(host, port)
                entry[1] = uwriter
            except Exception as e:  # noqa: BLE001
                self.stats.error(f"connection: {type(e).__name__}")
                log.debug("upstream error (%s): %r", self._label(host), e)
                if on_connect:
                    await on_connect(e)
                return
            if on_connect:
                await on_connect(None)
            up = asyncio.ensure_future(self._upstream(creader, uwriter, usock, host, cwriter))
            down = asyncio.ensure_future(self._copy(ureader, cwriter, uwriter, down=True))
            await asyncio.gather(up, down, return_exceptions=True)
        finally:
            self._conns.pop(id(cwriter), None)
            _close(uwriter)
            _close(cwriter)
            self.stats.conn_close()

    # ---- istemci -> sunucu -------------------------------------------------
    async def _upstream(self, creader, uwriter, usock, host, cwriter) -> None:
        try:
            data = await creader.read(CHUNK)
            if data:
                await self._first_flight(creader, uwriter, usock, data, host)
            await self._pump(creader, uwriter, down=False)
            _eof(uwriter)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            _close(uwriter)
            _close(cwriter)

    async def _copy(self, reader, writer, peer, down: bool) -> None:
        try:
            await self._pump(reader, writer, down)
            _eof(writer)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            _close(writer)
            _close(peer)

    async def _pump(self, reader, writer, down: bool) -> None:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                return
            writer.write(data)
            await writer.drain()
            if down:
                self.stats.bytes_down += len(data)
            else:
                self.stats.bytes_up += len(data)

    # ---- ilk veri uçuşu ----------------------------------------------------
    async def _first_flight(self, creader, uwriter, usock, data: bytes, host: str) -> None:
        target: Optional[Target] = None
        kind = ""
        if looks_like_tls(data):
            # Büyük (ör. Kyber'lı) ClientHello birden çok okumada gelebilir
            need = tls_record_total(data)
            while 0 < need <= 16389 and len(data) < need:
                more = await asyncio.wait_for(creader.read(CHUNK), 3.0)
                if not more:
                    break
                data += more
            target = parse_client_hello(data)
            kind = "tls"
        elif looks_like_http(data) and self.http_split:
            target = parse_http_request(data)
            kind = "http"
            if target is not None and self.host_case:
                data = mix_host_case(data, target)

        if kind:
            name = target.name if target and target.name else (host if not is_ip(host) else "")
            if not should_desync(self.filter_mode, self.filter_domains, name):
                kind = ""

        if not kind:
            self.stats.passthrough += 1
            uwriter.write(data)
            await uwriter.drain()
            return

        positions, delay, oob, tlsrec, disorder = self._st
        segments, how = plan_segments(data, target, kind, positions, tlsrec)
        if kind == "tls":
            self.stats.tls_split += 1
        else:
            self.stats.http_split += 1
        log.debug("splitting %s: %s, %s, %d pieces", self._label(host), kind, how, len(segments))
        await send_segments(uwriter, usock, segments, oob, disorder, delay, self.stats)


DISORDER_TTL = 1


async def send_segments(uwriter, usock, segments, oob: bool, disorder: bool, delay: float,
                        stats: Optional[Stats] = None) -> None:
    """Parçaları sırayla yazar. disorder: ilk parça TTL 1 ile gider; ilk router'da ölür,
    çekirdek onu varsayılan TTL ile yeniden iletir ve sunucuya parçalar sırasız ulaşır."""
    last = len(segments) - 1
    for i, seg in enumerate(segments):
        lowered = i == 0 and disorder and last > 0 and set_ttl(usock, DISORDER_TTL)
        if i == 0 and disorder and last > 0 and not lowered and stats is not None:
            stats.error("disorder: could not set TTL")
        try:
            uwriter.write(seg)
            await uwriter.drain()
        finally:
            if lowered and not set_ttl(usock, -1):
                raise OSError("could not restore TTL")
        if i == 0 and oob and last > 0:
            try:
                usock.send(b"\x00", socket.MSG_OOB)
            except OSError as e:
                log.debug("could not send OOB: %s", e)
        if i < last:
            await asyncio.sleep(delay)


def _eof(writer) -> None:
    try:
        if writer.can_write_eof():
            writer.write_eof()
    except Exception:
        pass
