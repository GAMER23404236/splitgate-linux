"""Birim testleri: ayrıştırıcılar, strateji, DNS tel biçimi, yapılandırma, nft kuralları."""
import os
import ssl
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import config, dnswire, firewall  # noqa: E402
from dpigec.strategy import (domain_matches, mix_host_case, resolve_positions,  # noqa: E402
                             should_desync, split_payload)
from dpigec.tlsparse import (looks_like_http, looks_like_tls, parse_client_hello,  # noqa: E402
                             parse_http_request, tls_record_total)


def make_client_hello(host: str) -> bytes:
    ctx = ssl.create_default_context()
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


class TlsParseTests(unittest.TestCase):
    def test_sni_offsets(self):
        for host in ("discord.com", "www.example.org", "a.b.c.example.com.tr"):
            ch = make_client_hello(host)
            self.assertTrue(looks_like_tls(ch))
            self.assertEqual(tls_record_total(ch), len(ch))
            t = parse_client_hello(ch)
            self.assertIsNotNone(t)
            self.assertEqual(t.name, host)
            self.assertEqual(ch[t.start:t.end].decode(), host)

    def test_garbage_and_truncated(self):
        ch = make_client_hello("discord.com")
        for cut in (3, 10, 43, 60, 100):
            self.assertIsNone(parse_client_hello(ch[:cut]) if cut < 80 else None)
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01\x00\x05hello"))
        self.assertIsNone(parse_client_hello(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertFalse(looks_like_tls(b"\x17\x03\x03"))

    def test_http_host(self):
        req = b"GET /x HTTP/1.1\r\nUser-Agent: t\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n"
        self.assertTrue(looks_like_http(req))
        t = parse_http_request(req)
        self.assertEqual(t.name, "Example.com")
        self.assertEqual(req[t.start:t.end], b"Example.com")
        self.assertEqual(t.method_end, 3)

    def test_http_no_host(self):
        t = parse_http_request(b"GET / HTTP/1.0\r\n\r\n")
        self.assertEqual(t.start, -1)


class StrategyTests(unittest.TestCase):
    def test_positions_tls(self):
        ch = make_client_hello("discord.com")
        t = parse_client_hello(ch)
        pos = resolve_positions(["1", "midsld"], len(ch), t)
        self.assertEqual(pos[0], 1)
        self.assertEqual(pos[1], t.start + len("discord") // 2)
        segs = split_payload(ch, pos)
        self.assertEqual(b"".join(segs), ch)
        self.assertEqual(len(segs), 3)
        # midsld ayrımı SNI'nin içinden geçmeli
        self.assertNotIn(b"discord.com", segs[1] + segs[2][:0])
        self.assertTrue(all(b"discord.com" not in s for s in segs))

    def test_midsld_two_part_tld(self):
        ch = make_client_hello("www.example.com.tr")
        t = parse_client_hello(ch)
        pos = resolve_positions(["midsld"], len(ch), t)
        label_start = t.start + len("www.")
        self.assertEqual(pos[0], label_start + len("example") // 2)

    def test_unknown_tokens_ignored_without_target(self):
        self.assertEqual(resolve_positions(["1", "sni", "midsld"], 100, None), [1])
        self.assertEqual(resolve_positions(["0", "100", "500"], 100, None), [])

    def test_http_split_and_case(self):
        req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n"
        t = parse_http_request(req)
        pos = resolve_positions(["method", "midsld"], len(req), t)
        segs = split_payload(req, pos)
        self.assertEqual(b"".join(segs), req)
        mixed = mix_host_case(req, t)
        self.assertEqual(len(mixed), len(req))
        self.assertIn(b"\r\nhOsT: blocked.example", mixed)

    def test_filters(self):
        self.assertTrue(domain_matches("a.discord.com", ["discord.com"]))
        self.assertFalse(domain_matches("notdiscord.com", ["discord.com"]))
        self.assertTrue(should_desync("all", [], "x.com"))
        self.assertTrue(should_desync("include", ["x.com"], "x.com"))
        self.assertFalse(should_desync("include", ["x.com"], "y.com"))
        self.assertFalse(should_desync("exclude", ["x.com"], "x.com"))
        self.assertTrue(should_desync("exclude", ["x.com"], ""))


class DnsWireTests(unittest.TestCase):
    def _answer(self, query, ips, ttl=60):
        qid, _f, qd, *_ = dnswire.parse_header(query)
        off = 12
        for _ in range(qd):
            off = dnswire._skip_name(query, off) + 4
        resp = struct.pack("!HHHHHH", qid, 0x8180, qd, len(ips), 0, 0) + query[12:off]
        for ip in ips:
            resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(map(int, ip.split(".")))
        return resp

    def test_roundtrip(self):
        q = dnswire.build_query("Discord.com", dnswire.QTYPE_A, qid=0x1234)
        self.assertTrue(dnswire.is_query(q))
        r = self._answer(q, ["1.2.3.4", "5.6.7.8"], ttl=42)
        rcode, addrs, ttl = dnswire.parse_answers(r)
        self.assertEqual((rcode, addrs, ttl), (0, ["1.2.3.4", "5.6.7.8"], 42))
        self.assertFalse(dnswire.is_query(r))

    def test_key_ignores_id_and_case(self):
        a = dnswire.build_query("DISCORD.com", 1, qid=1)
        b = dnswire.build_query("discord.COM", 1, qid=999)
        self.assertEqual(dnswire.question_key(a), dnswire.question_key(b))
        c = dnswire.build_query("discord.com", 28, qid=1)
        self.assertNotEqual(dnswire.question_key(a), dnswire.question_key(c))

    def test_servfail_and_truncate(self):
        q = dnswire.build_query("example.com", 1, qid=77)
        sf = dnswire.servfail(q)
        rcode, addrs, _ = dnswire.parse_answers(sf)
        self.assertEqual((rcode, addrs), (2, []))
        self.assertEqual(struct.unpack("!H", sf[:2])[0], 77)
        tr = dnswire.truncate(self._answer(q, ["1.1.1.1"]))
        self.assertTrue(tr[2] & 0x02)

    def test_bad_input(self):
        with self.assertRaises(dnswire.DNSError):
            dnswire.parse_header(b"abc")
        with self.assertRaises(dnswire.DNSError):
            dnswire.parse_answers(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x05ab")


class ConfigTests(unittest.TestCase):
    def test_defaults_valid(self):
        cfg = config.normalize(None)
        self.assertEqual(cfg["mode"], "transparent")
        st = config.effective_strategy(cfg)
        self.assertEqual(cfg["strategy"]["preset"], "sni")
        self.assertEqual(st["positions"], ["1", "sni"])

    def test_removed_turkiye_preset_is_migrated_to_default(self):
        self.assertNotIn("turkiye", config.PRESETS)
        cfg = config.normalize({"strategy": {"preset": "turkiye"}})
        self.assertEqual(cfg["strategy"]["preset"], "sni")
        with self.assertRaises(config.ConfigError):
            config.normalize({"strategy": {"preset": "nonsense"}})

    def test_merge_partial_and_unknown(self):
        cfg = config.normalize({"strategy": {"preset": "agresif"}, "zzz": 1})
        self.assertEqual(cfg["strategy"]["preset"], "agresif")
        self.assertEqual(cfg["dns"]["enabled"], True)
        self.assertNotIn("zzz", cfg)

    def test_rejects_bad_values(self):
        bad = [
            {"mode": "x"},
            {"listen_port": 80},
            {"listen_port": 2000, "dns_port": 2000},
            {"ports": [0]},
            {"ports": []},
            {"strategy": {"positions": ["abc"]}},
            {"strategy": {"preset": "yok"}},
            {"strategy": {"delay_ms": 9999}},
            {"dns": {"providers": ["evil"]}},
            {"dns": {"providers": ["custom"]}},
            {"domain_filter": {"domains": ["bad domain!"]}},
            {"fwmark": "1; flush ruleset"},
            {"ports": [80, "443; drop"]},
            "string",
        ]
        for b in bad:
            with self.assertRaises(config.ConfigError, msg=str(b)):
                config.normalize(b)

    def test_custom_provider_and_domains(self):
        cfg = config.normalize({
            "dns": {"providers": ["custom", "cloudflare"],
                    "custom": {"host": "dns.example.net", "ips": ["9.9.9.10"], "path": "/q"}},
            "domain_filter": {"mode": "include", "domains": ["*.Discord.com", "x.com", "x.com"]},
        })
        self.assertEqual(cfg["domain_filter"]["domains"], ["discord.com", "x.com"])

    def test_save_and_load(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sub", "c.json")
            cfg = config.normalize({"strategy": {"preset": "hafif"}})
            config.save_config(cfg, p)
            self.assertEqual(config.load_config(p)["strategy"]["preset"], "hafif")
            self.assertEqual(config.load_config(os.path.join(d, "yok.json"))["mode"], "transparent")
            with open(p, "w") as fh:
                fh.write("{bozuk")
            with self.assertRaises(config.ConfigError):
                config.load_config(p)


class FirewallRenderTests(unittest.TestCase):
    def test_render_variants(self):
        cfg = config.normalize({"gateway": True, "ports": [80, 443, 8080]})
        text = firewall.render_ruleset(cfg)
        self.assertIn("chain nat_prerouting", text)
        self.assertIn("tcp dport { 80, 443, 8080 } redirect to :18443", text)
        self.assertIn("chain quic_forward", text)
        off = config.normalize({"dns": {"enabled": False}, "quic_block": False})
        text = firewall.render_ruleset(off)
        self.assertNotIn("dport 53", text)
        self.assertNotIn("quic", text)
        no443 = config.normalize({"ports": [80]})
        self.assertNotIn("quic", firewall.render_ruleset(no443))

    def test_nft_syntax_check(self):
        import shutil
        if not shutil.which("nft") or os.geteuid() != 0:
            self.skipTest("nft yok veya root değil")
        for override in ({}, {"gateway": True}, {"dns": {"enabled": False}, "quic_block": False}):
            cfg = config.normalize(override)
            try:
                firewall.apply(cfg, check_only=True)
            except firewall.FirewallError as e:
                if "Operation not permitted" in str(e) or "Permission denied" in str(e):
                    self.skipTest("netlink yetkisi yok")
                raise


if __name__ == "__main__":
    unittest.main()
