"""Uçtan uca testler (yalnızca loopback):

 * Sahte DoH sunucusu -> DohClient / DohResolver / DnsProxy
 * "Durumsuz DPI" benzetimi: ilk TCP parçasında yasaklı SNI'yi görürse bağlantıyı keser
 * SOCKS5 ve HTTP CONNECT vekili -> bölme sayesinde TLS el sıkışması başarılı olmalı
 * probe.tls_probe aynı DPI benzetimine karşı
"""
import asyncio
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import config, dnswire  # noqa: E402
from dpigec.dnsserver import DnsProxy  # noqa: E402
from dpigec.doh import DohClient, DohResolver, Provider  # noqa: E402
from dpigec.probe import tls_probe  # noqa: E402
from dpigec.relay import Relay  # noqa: E402
from dpigec.socks import ProxyServer  # noqa: E402
from dpigec.stats import Stats  # noqa: E402

BLOCKED = "blocked.test"
MARK = 17488


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_cert(dirpath: str, cn: str):
    key, crt = os.path.join(dirpath, f"{cn}.key"), os.path.join(dirpath, f"{cn}.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
         "-days", "2", "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}"],
        check=True, capture_output=True)
    return key, crt


class Env:
    """Ortak test altyapısı: sertifikalar, TLS sunucusu, DPI benzetimi, sahte DoH."""

    async def setup(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        key, self.crt = make_cert(d, BLOCKED)
        self.client_ctx = ssl.create_default_context(cafile=self.crt)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(self.crt, key)

        # 1) Gerçek TLS sunucusu
        async def tls_handler(r, w):
            try:
                w.write(b"merhaba-dpi")
                await w.drain()
                await r.read(10)
            finally:
                w.close()

        self.tls_server = await asyncio.start_server(tls_handler, "127.0.0.1", 0, ssl=sctx)
        tls_port = self.tls_server.sockets[0].getsockname()[1]

        # 2) Durumsuz DPI benzetimi: ilk okunan parçada yasaklı SNI varsa keser
        self.dpi_blocked = 0

        async def dpi_handler(cr, cw):
            first = await cr.read(65536)
            if not first or BLOCKED.encode() in first:
                self.dpi_blocked += 1
                cw.transport.abort()
                return
            ur, uw = await asyncio.open_connection("127.0.0.1", tls_port)
            uw.write(first)

            async def pipe(a, b):
                try:
                    while True:
                        data = await a.read(65536)
                        if not data:
                            break
                        b.write(data)
                        await b.drain()
                except ConnectionError:
                    pass
                finally:
                    b.close()

            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))

        self.dpi_server = await asyncio.start_server(dpi_handler, "127.0.0.1", 0)
        self.dpi_port = self.dpi_server.sockets[0].getsockname()[1]

        # 3) Sahte DoH sunucusu (her A sorgusuna 127.0.0.1 döndürür)
        dkey, dcrt = make_cert(d, "doh.test")
        dctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        dctx.load_cert_chain(dcrt, dkey)
        self.doh_queries = 0

        async def doh_handler(r, w):
            try:
                while True:
                    head = await r.readuntil(b"\r\n\r\n")
                    n = int([ln.split(b":")[1] for ln in head.split(b"\r\n")
                             if ln.lower().startswith(b"content-length")][0])
                    q = await r.readexactly(n)
                    self.doh_queries += 1
                    qid, _f, qd, *_ = dnswire.parse_header(q)
                    off = 12
                    for _ in range(qd):
                        off = dnswire._skip_name(q, off) + 4
                    is_a = struct.unpack_from("!H", q, off - 4)[0] == 1
                    resp = struct.pack("!HHHHHH", qid, 0x8180, qd, 1 if is_a else 0, 0, 0) + q[12:off]
                    if is_a:
                        resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
                    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                            b"Content-Length: " + str(len(resp)).encode() + b"\r\n\r\n" + resp)
                    await w.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                w.close()

        self.doh_server = await asyncio.start_server(doh_handler, "127.0.0.1", 0, ssl=dctx)
        self.doh_port = self.doh_server.sockets[0].getsockname()[1]
        self.doh_ctx = ssl.create_default_context(cafile=dcrt)
        self.stats = Stats()
        self.doh = DohClient([Provider("test", "doh.test", ["127.0.0.1"], port=self.doh_port)],
                             MARK, 3, False, self.stats, self.doh_ctx)

    async def teardown(self):
        self.doh.close()
        for s in (self.tls_server, self.dpi_server, self.doh_server):
            s.close()
        self.tmp.cleanup()

    def relay(self, **strategy):
        cfg = config.normalize({"strategy": {"preset": "custom", "positions": ["1", "midsld"],
                                             "delay_ms": 25, **strategy},
                                "ipv6": False})
        resolver = DohResolver(self.doh, False, 60)
        return Relay(cfg, self.stats, resolver), cfg


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = Env()
        await self.env.setup()

    async def asyncTearDown(self):
        await self.env.teardown()

    # ---- DoH ---------------------------------------------------------------
    async def test_doh_and_resolver_cache(self):
        res = DohResolver(self.env.doh, False, 60)
        self.assertEqual(await res.resolve(BLOCKED), ["127.0.0.1"])
        n = self.env.doh_queries
        self.assertEqual(await res.resolve(BLOCKED), ["127.0.0.1"])
        self.assertEqual(self.env.doh_queries, n)  # önbellekten
        self.assertEqual(await res.resolve("10.1.2.3"), ["10.1.2.3"])  # IP değişmez

    async def test_dns_proxy_udp_tcp_cache(self):
        proxy = DnsProxy(self.env.doh, self.env.stats, 60)
        port = free_port()
        await proxy.start(port, False, False)
        try:
            loop = asyncio.get_running_loop()
            q = dnswire.build_query("anything.test", 1, qid=4242)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.sendto(q, ("127.0.0.1", port))
            data = await asyncio.wait_for(loop.sock_recv(sock, 4096), 3)
            sock.close()
            self.assertEqual(struct.unpack("!H", data[:2])[0], 4242)
            self.assertEqual(dnswire.parse_answers(data)[1], ["127.0.0.1"])

            # aynı soru, farklı ID: önbellekten ve ID'si yeniden yazılmış
            q2 = dnswire.build_query("ANYTHING.test", 1, qid=7)
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(struct.pack("!H", len(q2)) + q2)
            n = struct.unpack("!H", await r.readexactly(2))[0]
            data2 = await r.readexactly(n)
            w.close()
            self.assertEqual(struct.unpack("!H", data2[:2])[0], 7)
            self.assertEqual(self.env.stats.dns_cached, 1)
        finally:
            await proxy.stop()

    async def test_dns_proxy_servfail_when_doh_down(self):
        dead = DohClient([Provider("dead", "doh.test", ["127.0.0.1"], port=free_port())],
                         MARK, 1, False, Stats(), self.env.doh_ctx)
        proxy = DnsProxy(dead, Stats(), 0)
        q = dnswire.build_query("x.test", 1, qid=5)
        resp = await proxy.handle(q)
        self.assertEqual(dnswire.parse_answers(resp)[0], 2)

    # ---- DPI benzetimi doğrulaması ----------------------------------------
    async def test_dpi_simulator_blocks_direct_connection(self):
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            r, w = await asyncio.open_connection("127.0.0.1", self.env.dpi_port)
            await w.start_tls(self.env.client_ctx, server_hostname=BLOCKED)
            await r.read(5)
        self.assertGreaterEqual(self.env.dpi_blocked, 1)

    # ---- SOCKS5 / HTTP CONNECT --------------------------------------------
    async def _start_proxy(self, **strategy):
        relay, cfg = self.env.relay(**strategy)
        server = ProxyServer(relay)
        port = free_port()
        await server.start(port, False, False)
        return server, relay, port

    async def _tls_over_socks(self, port: int, host: str, dport: int):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"\x05\x01\x00")
        self.assertEqual(await r.readexactly(2), b"\x05\x00")
        hb = host.encode()
        w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", dport))
        rep = await r.readexactly(10)
        self.assertEqual(rep[1], 0, "SOCKS yanıtı başarısız")
        await w.start_tls(self.env.client_ctx, server_hostname=BLOCKED)
        data = await asyncio.wait_for(r.read(32), 5)
        w.close()
        return data

    async def test_socks5_split_defeats_dpi(self):
        server, relay, port = await self._start_proxy()
        try:
            data = await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
            self.assertEqual(data, b"merhaba-dpi")
            self.assertEqual(self.env.stats.tls_split, 1)
        finally:
            await server.stop()

    async def test_socks5_without_split_is_blocked(self):
        # Konum yok -> bölme yok -> DPI benzetimi keser (testin anlamlı olduğunu kanıtlar)
        server, relay, port = await self._start_proxy(positions=["9999"])
        try:
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError, asyncio.IncompleteReadError)):
                await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
        finally:
            await server.stop()

    async def test_socks5_oob_variant(self):
        server, relay, port = await self._start_proxy(oob=True)
        try:
            data = await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
            self.assertEqual(data, b"merhaba-dpi")
        finally:
            await server.stop()

    async def test_socks5_tls_record_split_defeats_dpi(self):
        server, relay, port = await self._start_proxy(positions=["hostmid"], tlsrec=True)
        try:
            data = await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
            self.assertEqual(data, b"merhaba-dpi")
        finally:
            await server.stop()

    async def test_socks5_disorder_variant_still_delivers(self):
        # loopback'te TTL 1 paketi düşmez; burada yalnızca akışın bozulmadığı doğrulanır.
        server, relay, port = await self._start_proxy(positions=["hostmid"], tlsrec=True, disorder=True)
        try:
            data = await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
            self.assertEqual(data, b"merhaba-dpi")
        finally:
            await server.stop()

    async def test_http_connect(self):
        server, relay, port = await self._start_proxy()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"CONNECT {BLOCKED}:{self.env.dpi_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            line = await r.readuntil(b"\r\n\r\n")
            self.assertTrue(line.startswith(b"HTTP/1.1 200"))
            await w.start_tls(self.env.client_ctx, server_hostname=BLOCKED)
            self.assertEqual(await asyncio.wait_for(r.read(32), 5), b"merhaba-dpi")
            w.close()
        finally:
            await server.stop()

    async def test_socks_connect_failure_reply(self):
        server, relay, port = await self._start_proxy()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            await r.readexactly(2)
            w.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", free_port()))
            rep = await r.readexactly(10)
            self.assertEqual(rep[1], 5)  # bağlantı reddedildi
            w.close()
        finally:
            await server.stop()

    async def test_domain_filter_exclude_passes_through(self):
        server, relay, port = await self._start_proxy()
        relay.filter_mode, relay.filter_domains = "exclude", [BLOCKED]
        try:
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError, asyncio.IncompleteReadError)):
                await self._tls_over_socks(port, BLOCKED, self.env.dpi_port)
            self.assertEqual(self.env.stats.passthrough >= 1, True)
        finally:
            await server.stop()

    async def test_plain_http_split(self):
        # düz HTTP: Host adı DPI benzetimince görülemeyecek biçimde bölünür
        seen = []

        async def http_dpi(cr, cw):
            first = await cr.read(65536)
            seen.append(first)
            if BLOCKED.encode() in first:
                cw.transport.abort()
                return
            rest = b""
            try:
                rest = await asyncio.wait_for(cr.read(65536), 1)
            except asyncio.TimeoutError:
                pass
            cw.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await cw.drain()
            cw.close()

        srv = await asyncio.start_server(http_dpi, "127.0.0.1", 0)
        hport = srv.sockets[0].getsockname()[1]
        server, relay, port = await self._start_proxy()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            await r.readexactly(2)
            hb = BLOCKED.encode()
            w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", hport))
            self.assertEqual((await r.readexactly(10))[1], 0)
            w.write(f"GET / HTTP/1.1\r\nHost: {BLOCKED}\r\n\r\n".encode())
            await w.drain()
            body = await asyncio.wait_for(r.read(200), 5)
            self.assertIn(b"200 OK", body)
            self.assertEqual(self.env.stats.http_split, 1)
            w.close()
        finally:
            await server.stop()
            srv.close()

    # ---- probe -------------------------------------------------------------
    async def test_probe_with_and_without_split(self):
        ok = await tls_probe("127.0.0.1", BLOCKED, ["1", "midsld"], 0.025, False, MARK, 5,
                             self.env.client_ctx, self.env.dpi_port)
        self.assertGreater(ok, 0)
        with self.assertRaises((ConnectionError, ssl.SSLError, OSError, asyncio.TimeoutError)):
            await tls_probe("127.0.0.1", BLOCKED, [], 0.0, False, MARK, 3,
                            self.env.client_ctx, self.env.dpi_port)
        ok = await tls_probe("127.0.0.1", BLOCKED, ["hostmid"], 0.0, False, MARK, 5,
                             self.env.client_ctx, self.env.dpi_port, tlsrec=True, disorder=True)
        self.assertGreater(ok, 0)


if __name__ == "__main__":
    unittest.main()
