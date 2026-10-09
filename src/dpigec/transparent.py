"""Şeffaf (REDIRECT) TCP dinleyicisi: özgün hedefi SO_ORIGINAL_DST ile bulur."""
from __future__ import annotations

import asyncio
import logging
import socket

from .relay import Relay
from .sockutil import listen_socket, original_dst

log = logging.getLogger("dpigec.transparent")


class TransparentServer:
    def __init__(self, relay: Relay, listen_port: int) -> None:
        self.relay = relay
        self.listen_port = listen_port
        self._servers = []

    async def start(self, gateway: bool, ipv6: bool) -> None:
        # IPv4 ve IPv6 ayrı dinleyiciler: SO_ORIGINAL_DST aileye göre okunur.
        fams = [(socket.AF_INET, "0.0.0.0")]
        if ipv6:
            fams.append((socket.AF_INET6, "::"))
        for fam, host in fams:
            try:
                srv = await asyncio.start_server(
                    self._client, sock=listen_socket(fam, host, self.listen_port))
                self._servers.append(srv)
            except OSError as e:
                if fam == socket.AF_INET6:
                    log.warning("could not open the IPv6 transparent listener: %s", e)
                    continue
                raise
        log.info("transparent proxy listening: port %d", self.listen_port)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        self._servers.clear()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        dst = original_dst(sock) if sock is not None else None
        # Özgün hedef alınamıyorsa (doğrudan bağlantı) ya da kendi portumuzsa reddet.
        if dst is None or dst[1] == self.listen_port:
            writer.close()
            return
        try:
            await self.relay.serve(reader, writer, dst[0], dst[1])
        except Exception:  # noqa: BLE001
            log.exception("transparent client error")
            writer.close()
