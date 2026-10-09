"""Yerel DNS vekili: UDP/TCP 53 sorgularını DoH'a aktarır (önbellekli)."""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from typing import Dict, List, Tuple

from . import dnswire
from .doh import DohClient, DohError
from .sockutil import listen_socket
from .stats import Stats

log = logging.getLogger("dpigec.dns")


class DnsProxy:
    def __init__(self, doh: DohClient, stats: Stats, cache_seconds: int = 300) -> None:
        self.doh = doh
        self.stats = stats
        self.cache_seconds = cache_seconds
        self._cache: Dict[bytes, Tuple[float, bytes]] = {}
        self._servers: List[asyncio.AbstractServer] = []
        self._transports: List[asyncio.BaseTransport] = []

    def flush(self) -> None:
        """Ağ değişince: önceki ağa özgü olabilecek cevaplar (CDN adresleri) atılır."""
        self._cache.clear()

    # ---- çekirdek ----------------------------------------------------------
    async def handle(self, query: bytes) -> bytes:
        """Tek bir DNS sorgusunu yanıtlar (hata olursa SERVFAIL)."""
        self.stats.dns_queries += 1
        try:
            if not dnswire.is_query(query):
                raise dnswire.DNSError("not a query")
            key = dnswire.question_key(query)
        except dnswire.DNSError:
            self.stats.dns_failed += 1
            return b""
        qid = struct.unpack_from("!H", query, 0)[0]
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            self.stats.dns_cached += 1
            return dnswire.set_id(hit[1], qid)
        try:
            resp = await self.doh.query(query)
        except (DohError, OSError, asyncio.TimeoutError) as e:
            self.stats.dns_failed += 1
            self.stats.error(f"DoH: {e}")
            return dnswire.servfail(query)
        resp = dnswire.set_id(resp, qid)
        self._store(key, resp)
        return resp

    def _store(self, key: bytes, resp: bytes) -> None:
        if not self.cache_seconds:
            return
        try:
            rcode, addrs, ttl = dnswire.parse_answers(resp)
        except dnswire.DNSError:
            return
        if rcode != 0 or not addrs:
            return
        if len(self._cache) > 2048:
            for k in list(self._cache)[:512]:
                self._cache.pop(k, None)
        self._cache[key] = (time.monotonic() + min(max(ttl, 10), self.cache_seconds), resp)

    # ---- UDP ---------------------------------------------------------------
    def _udp_protocol(self):
        proxy = self

        class _Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                asyncio.ensure_future(self._answer(data, addr))

            async def _answer(self, data, addr):
                resp = await proxy.handle(data)
                if resp:
                    if len(resp) > 4096:  # UDP için çok büyükse TC bitiyle kısalt
                        try:
                            resp = dnswire.truncate(resp)
                        except dnswire.DNSError:
                            return
                    try:
                        self.transport.sendto(resp, addr)
                    except OSError:
                        pass

        return _Proto()

    # ---- TCP ---------------------------------------------------------------
    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                hdr = await asyncio.wait_for(reader.readexactly(2), 30)
                n = struct.unpack("!H", hdr)[0]
                if n < 12:
                    break
                query = await asyncio.wait_for(reader.readexactly(n), 10)
                resp = await self.handle(query)
                if not resp:
                    break
                writer.write(struct.pack("!H", len(resp)) + resp)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ---- yaşam döngüsü -----------------------------------------------------
    async def start(self, port: int, gateway: bool, ipv6: bool) -> None:
        loop = asyncio.get_running_loop()
        hosts = [(socket.AF_INET, "0.0.0.0" if gateway else "127.0.0.1")]
        if ipv6:
            hosts.append((socket.AF_INET6, "::" if gateway else "::1"))
        for fam, host in hosts:
            try:
                tcp = listen_socket(fam, host, port)
                self._servers.append(await asyncio.start_server(self._tcp_client, sock=tcp))
                udp = socket.socket(fam, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if fam == socket.AF_INET6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind((host, port))
                udp.setblocking(False)
                transport, _ = await loop.create_datagram_endpoint(self._udp_protocol, sock=udp)
                self._transports.append(transport)
            except OSError as e:
                if fam == socket.AF_INET6:
                    log.warning("could not open the IPv6 DNS listener: %s", e)
                    continue
                raise
        log.info("DNS proxy listening: port %d", port)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        for t in self._transports:
            t.close()
        self._servers.clear()
        self._transports.clear()
