"""Yerel vekil: aynı portta SOCKS5 (CONNECT) ve HTTP CONNECT."""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional

from .relay import Relay
from .sockutil import listen_socket

log = logging.getLogger("dpigec.socks")

_REP_FAIL, _REP_HOST_UNREACH, _REP_REFUSED, _REP_CMD = 0x01, 0x04, 0x05, 0x07


def _reply_code(exc: BaseException) -> int:
    if isinstance(exc, ConnectionRefusedError):
        return _REP_REFUSED
    if isinstance(exc, OSError):
        return _REP_HOST_UNREACH
    return _REP_FAIL


class ProxyServer:
    def __init__(self, relay: Relay) -> None:
        self.relay = relay
        self._servers = []

    async def start(self, port: int, gateway: bool, ipv6: bool) -> None:
        hosts = [(socket.AF_INET, "0.0.0.0" if gateway else "127.0.0.1")]
        if ipv6:
            hosts.append((socket.AF_INET6, "::" if gateway else "::1"))
        for fam, host in hosts:
            try:
                srv = await asyncio.start_server(self._client, sock=listen_socket(fam, host, port))
                self._servers.append(srv)
            except OSError as e:
                if fam == socket.AF_INET6:
                    log.warning("could not open the IPv6 proxy listener: %s", e)
                    continue
                raise
        log.info("SOCKS5/HTTP proxy listening: port %d", port)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        self._servers.clear()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 15)
            if first == b"\x05":
                await self._socks5(reader, writer)
            elif first in (b"C", b"c"):
                await self._http_connect(first, reader, writer)
            else:
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            writer.close()
        except Exception:  # noqa: BLE001
            log.exception("proxy client error")
            writer.close()

    # ---- SOCKS5 ------------------------------------------------------------
    async def _socks5(self, reader, writer) -> None:
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            writer.close()
            return
        writer.write(b"\x05\x00")
        ver, cmd, _rsv, atyp = await reader.readexactly(4)
        if ver != 5:
            writer.close()
            return
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            raw = await reader.readexactly(n)
            try:
                host = raw.decode("ascii")
            except UnicodeDecodeError:
                try:
                    host = raw.decode("utf-8").encode("idna").decode("ascii")
                except UnicodeError:
                    await self._socks_reply(writer, 0x08)
                    writer.close()
                    return
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            await self._socks_reply(writer, 0x08)
            writer.close()
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        if cmd != 1:
            await self._socks_reply(writer, _REP_CMD)
            writer.close()
            return

        async def on_connect(exc: Optional[BaseException]) -> None:
            await self._socks_reply(writer, 0 if exc is None else _reply_code(exc))

        await self.relay.serve(reader, writer, host, port, on_connect)

    @staticmethod
    async def _socks_reply(writer, code: int) -> None:
        writer.write(bytes([5, code, 0, 1]) + b"\x00\x00\x00\x00\x00\x00")
        await writer.drain()

    # ---- HTTP CONNECT ------------------------------------------------------
    async def _http_connect(self, first: bytes, reader, writer) -> None:
        head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target = parts[1]
        if target.startswith("["):
            host, _, rest = target[1:].partition("]")
            port_s = rest.lstrip(":")
        else:
            host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s or "443")
            if not host or not 0 < port < 65536:
                raise ValueError
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        async def on_connect(exc: Optional[BaseException]) -> None:
            if exc is None:
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()

        await self.relay.serve(reader, writer, host, port, on_connect)
