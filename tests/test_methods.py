"""TLS + TCP bölme, sıra bozma (TTL), teşhis ve "gerçekten aşıyor mu" kuralları."""
import asyncio
import os
import ssl
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import config, probe, relay  # noqa: E402
from dpigec.strategy import plan_segments, tls_record_split  # noqa: E402
from dpigec.tlsparse import parse_client_hello, parse_http_request  # noqa: E402


def make_client_hello(host: str) -> bytes:
    ctx = ssl.create_default_context()
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


class TlsRecordTests(unittest.TestCase):
    def setUp(self):
        self.ch = make_client_hello("discord.com")
        self.t = parse_client_hello(self.ch)

    def test_two_valid_records_with_same_body(self):
        cut = self.t.start + 5
        rec = tls_record_split(self.ch, cut)
        r1_len = int.from_bytes(rec[3:5], "big")
        self.assertEqual(5 + r1_len, cut)
        r2 = rec[cut:]
        self.assertEqual(r2[:3], self.ch[:3])
        self.assertEqual(int.from_bytes(r2[3:5], "big"), len(r2) - 5)
        self.assertEqual(rec[5:cut] + r2[5:], self.ch[5:])

    def test_incomplete_or_outside(self):
        self.assertIsNone(tls_record_split(self.ch[:self.t.start + 20], self.t.start + 5))
        self.assertIsNone(tls_record_split(self.ch, 3))
        self.assertIsNone(tls_record_split(self.ch, len(self.ch)))

    def test_plan_tlsrec_cuts_middle_of_whole_name(self):
        segs, how = plan_segments(self.ch, self.t, "tls", ["hostmid"], True)
        self.assertEqual(len(segs), 2)
        self.assertEqual(len(segs[0]), self.t.start + 5)  # disco|rd.com, eski sürüm gibi
        self.assertIn("TLS record", how)

    def test_plan_tlsrec_incomplete_still_tcp_split(self):
        part = self.ch[:self.t.start + 20]
        segs, how = plan_segments(part, parse_client_hello(part), "tls", ["hostmid"], True)
        self.assertEqual(b"".join(segs), part)
        self.assertEqual(len(segs[0]), self.t.start + 5)
        self.assertIn("record not split", how)

    def test_plan_tlsrec_http(self):
        req = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        t = parse_http_request(req)
        segs, _ = plan_segments(req, t, "http", ["hostmid"], True)
        self.assertEqual(b"".join(segs), req)
        self.assertEqual(len(segs[0]), t.start + 5)

    def test_presets_have_new_methods(self):
        for key in ("tlskayit", "disorder", "disordersni", "tlsdisorder"):
            self.assertIn(key, config.PRESETS)
        self.assertTrue(config.PRESETS["tlsdisorder"]["tlsrec"] and config.PRESETS["tlsdisorder"]["disorder"])
        cfg = config.normalize({"strategy": {"preset": "tlsdisorder"}})
        st = config.effective_strategy(cfg)
        self.assertTrue(st["tlsrec"] and st["disorder"])
        with self.assertRaises(config.ConfigError):
            config.normalize({"strategy": {"preset": "custom", "disorder": "yes"}})


class FakeWriter:
    def __init__(self, ev, fail=False):
        self.ev, self.fail = ev, fail

    def write(self, data):
        if self.fail:
            raise ConnectionResetError("broken")
        self.ev.append(f"write {len(data)}")

    async def drain(self):
        pass


class DisorderSendTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, segs, disorder, fail=False):
        ev = []
        with mock.patch.object(relay, "set_ttl", side_effect=lambda s, t: ev.append(f"ttl {t}") or True):
            await relay.send_segments(FakeWriter(ev, fail), None, segs, False, disorder, 0)
        return ev

    async def test_ttl_only_around_first_piece(self):
        ev = await self._run([b"a", b"bcd", b"ef"], True)
        self.assertEqual(ev, ["ttl 1", "write 1", "ttl -1", "write 3", "write 2"])

    async def test_no_ttl_without_disorder_or_single_piece(self):
        self.assertEqual(await self._run([b"a", b"b"], False), ["write 1", "write 1"])
        self.assertEqual(await self._run([b"abc"], True), ["write 3"])

    async def test_ttl_restored_when_write_fails(self):
        ev = []
        with mock.patch.object(relay, "set_ttl", side_effect=lambda s, t: ev.append(f"ttl {t}") or True):
            with self.assertRaises(ConnectionResetError):
                await relay.send_segments(FakeWriter(ev, True), None, [b"a", b"b"], False, True, 0)
        self.assertEqual(ev, ["ttl 1", "ttl -1"])

    def test_real_socket_ttl_set_and_reset(self):
        import socket
        from dpigec.sockutil import set_ttl
        for fam in (socket.AF_INET, socket.AF_INET6):
            s = socket.socket(fam, socket.SOCK_STREAM)
            try:
                self.assertTrue(set_ttl(s, 1))
                opt = (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS) if fam == socket.AF_INET6 \
                    else (socket.IPPROTO_IP, socket.IP_TTL)
                self.assertEqual(s.getsockopt(*opt), 1)
                self.assertTrue(set_ttl(s, -1))
                self.assertGreater(s.getsockopt(*opt), 1)
            finally:
                s.close()


def res(key, *codes):
    """codes: None = açıldı, aksi halde hata kodu."""
    per = {}
    for i, c in enumerate(codes):
        per[f"d{i}.example"] = {"ok": True, "ms": 50} if c is None else {"ok": False, "code": c, "err": c}
    ok = sum(1 for c in codes if c is None)
    return {"preset": key, "label": key, "ok": ok, "total": len(codes), "avg_ms": 50 if ok else None,
            "domains": per}


R, T, C, D = probe.ERR_RESET, probe.ERR_TIMEOUT, probe.ERR_CONNECT_TIMEOUT, probe.ERR_DNS


class VerdictTests(unittest.TestCase):
    def test_works_requires_real_bypass(self):
        results = [res("none", None, R, R), res("sni", None, R, R), res("oob", None, T, R)]
        self.assertFalse(probe.bypasses(results, results[1]))
        self.assertIsNone(probe.best_preset(results))
        self.assertEqual(probe.diagnose(results), probe.DPI_UNBEATEN)
        results.append(res("tlsdisorder", None, None, R))
        self.assertEqual(probe.best_preset(results), "tlsdisorder")
        self.assertEqual(probe.diagnose(results), probe.WORKS)

    def test_verdicts(self):
        self.assertEqual(probe.diagnose([res("none", None, None), res("sni", None, None)]), probe.NOT_BLOCKED)
        self.assertEqual(probe.diagnose([res("none", D, D), res("sni", D, D)]), probe.DNS_FAILED)
        self.assertEqual(probe.diagnose([res("none", C, C), res("sni", C, C)]), probe.IP_BLOCK)
        self.assertEqual(probe.diagnose([res("none", probe.ERR_CERT, probe.ERR_CERT)]), probe.INTERCEPTED)
        self.assertEqual(probe.diagnose([res("none", probe.ERR_UNREACHABLE, probe.ERR_UNREACHABLE)]),
                         probe.NO_CONNECTION)
        self.assertEqual(probe.diagnose([]), probe.DNS_FAILED)

    def test_tie_is_not_ip_block(self):
        self.assertEqual(probe.diagnose([res("none", C, C, R, R), res("sni", C, C, R, T)]), probe.DPI_UNBEATEN)

    def test_dns_failure_does_not_hide_not_blocked(self):
        results = [res("none", None, None, D)]
        self.assertTrue(probe.not_blocked(results))
        self.assertEqual(probe.reachable(results[0]), 2)

    def test_baseline_dns_failure_is_not_a_bypass(self):
        results = [res("none", None, D), res("sni", None, None)]
        self.assertFalse(probe.bypasses(results, results[1]))
        self.assertIsNone(probe.best_preset(results))

    def test_each_site_resolved_once_per_run(self):
        calls = []

        class Resolver:
            async def resolve(self, host):
                calls.append(host)
                raise OSError("doh down")

        async def run():
            with mock.patch.object(probe, "DohResolver", lambda *a, **k: Resolver()), \
                    mock.patch.object(probe, "DohClient") as client:
                client.return_value.close = lambda: None
                return await probe.run_probe(config.default_config(), ["a.example", "b.example"])
        results = asyncio.run(run())
        self.assertEqual(sorted(calls), ["a.example", "b.example"])
        self.assertEqual(len(results), 1 + len(config.PRESETS))
        self.assertEqual(probe.diagnose(results), probe.DNS_FAILED)

    def test_classify(self):
        self.assertEqual(probe.classify(ConnectionResetError()), probe.ERR_RESET)
        self.assertEqual(probe.classify(ConnectionRefusedError()), probe.ERR_REFUSED)
        self.assertEqual(probe.classify(OSError(101, "Network is unreachable")), probe.ERR_UNREACHABLE)
        self.assertEqual(probe.classify(asyncio.TimeoutError()), probe.ERR_TIMEOUT)
        self.assertEqual(probe.classify(probe._ConnectTimeout()), probe.ERR_CONNECT_TIMEOUT)
        self.assertEqual(probe.classify(ConnectionError("connection closed (EOF)")), probe.ERR_CLOSED)

    def test_plans_baseline_first(self):
        plans = probe.plans_for(["tlsdisorder"])
        self.assertEqual([p[0] for p in plans], ["none", "tlsdisorder"])
        self.assertEqual(len(probe.plans_for()), 1 + len(config.PRESETS))


if __name__ == "__main__":
    unittest.main()
