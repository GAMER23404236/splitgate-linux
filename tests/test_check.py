"""Ağ izleyici ve gerçek kontrol (sahte probe ile; ağa çıkmaz)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import checker, config, netwatch, probe  # noqa: E402

ROUTE = """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	700	00000000	0	0	0
wlan0	00000000	23DA890A	0003	0	0	600	00000000	0	0	0
wlan0	00DA890A	00000000	0001	0	0	600	00FFFFFF	0	0	0
"""


class NetwatchTests(unittest.TestCase):
    def test_gateway_mac_from_arp(self):
        arp = ("IP address       HW type     Flags       HW address            Mask     Device\n"
               "10.137.218.35    0x1         0x2         EE:53:38:B7:18:7A     *        wlan0\n"
               "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "arp")
            with open(p, "w") as fh:
                fh.write(arp)
            self.assertEqual(netwatch.gateway_mac("10.137.218.35", p), "ee:53:38:b7:18:7a")
            self.assertEqual(netwatch.gateway_mac("10.0.0.9", p), "")
            self.assertEqual(netwatch.gateway_mac("1.2.3.4", p), "")
            self.assertEqual(netwatch.gateway_mac("1.2.3.4", os.path.join(d, "none")), "")

    def test_same_ignores_unknown_mac_only(self):
        a = netwatch.NetId("wifi:w:1.1.1.1", "x", "")
        b = netwatch.NetId("wifi:w:1.1.1.1", "x", "aa:aa:aa:aa:aa:aa")
        c = netwatch.NetId("wifi:w:1.1.1.1", "x", "bb:bb:bb:bb:bb:bb")
        self.assertTrue(netwatch.same(a, b) and netwatch.same(b, a))
        self.assertFalse(netwatch.same(b, c))
        self.assertFalse(netwatch.same(b, netwatch.NetId("eth:e:1.1.1.1", "x")))
        self.assertTrue(netwatch.same(None, None))
        self.assertFalse(netwatch.same(a, None))

    def test_lowest_metric_default_route(self):
        self.assertEqual(netwatch.parse_default_route(ROUTE), ("wlan0", "10.137.218.35"))

    def test_no_default_route(self):
        self.assertIsNone(netwatch.parse_default_route(ROUTE.splitlines()[0] + "\n" + ROUTE.splitlines()[3]))

    def test_current_kind_and_label(self):
        with tempfile.TemporaryDirectory() as d:
            route = os.path.join(d, "route")
            with open(route, "w") as fh:
                fh.write(ROUTE)
            os.makedirs(os.path.join(d, "net", "wlan0", "wireless"))
            n = netwatch.current(route, os.path.join(d, "net"))
            self.assertEqual(n.key, "wifi:wlan0:10.137.218.35")
            self.assertEqual(n.label, "Wi-Fi (wlan0)")
            self.assertIsNone(netwatch.current(os.path.join(d, "missing")))


def res(key, *codes):
    per = {}
    for i, c in enumerate(codes):
        per[f"d{i}.example"] = {"ok": True, "ms": 40} if c is None else {"ok": False, "code": c, "err": c}
    ok = sum(1 for c in codes if c is None)
    return {"preset": key, "label": key, "ok": ok, "total": len(codes), "avg_ms": 40 if ok else None,
            "domains": per}


R, D = probe.ERR_RESET, probe.ERR_DNS


class FakeNet:
    """Ön ayar -> o ön ayarın sonucu (kodlar); "none" taban çizgisi."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    async def __call__(self, cfg, domains, progress, presets):
        keys = [p[0] for p in presets]
        self.calls.append(keys)
        return [res(k, *self.table.get(k, (R, R))) for k in keys]


class CheckerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "networks.json")
        self.cfg = config.default_config()
        self.net = netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)")
        self.applied = []

    def tearDown(self):
        self.tmp.cleanup()

    def mk(self, table):
        fake = FakeNet(table)
        return checker.Checker(self.cfg, fake, self.path), fake

    async def test_working_only_if_method_bypasses(self):
        c, fake = self.mk({"none": (R, R), "sni": (None, R)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.WORKING)
        self.assertEqual(r["detail"], "1/2")
        self.assertEqual(fake.calls, [["none", "sni"]])
        self.assertEqual(self.applied, [])

    async def test_unblocked_site_is_not_working(self):
        c, fake = self.mk({"none": (None, R), "sni": (None, R)})
        self.cfg["auto_method"] = False
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.FAILED)
        self.assertEqual(r["verdict"], probe.DPI_UNBEATEN)

    async def test_not_blocked(self):
        c, _ = self.mk({"none": (None, None), "sni": (None, None)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.NOT_BLOCKED)

    async def test_switches_to_working_method_and_saves_it(self):
        c, fake = self.mk({"none": (R, R), "sni": (R, R), "tlsdisorder": (None, None)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.WORKING)
        self.assertEqual(r["preset"], "tlsdisorder")
        self.assertEqual(self.applied, ["tlsdisorder"])
        self.assertEqual(checker.load_networks(self.path)[self.net.key]["preset"], "tlsdisorder")
        # sonraki seferde kayıtlı yöntem tam testten önce denenir
        c2, fake2 = self.mk({"none": (R, R), "sni": (R, R), "tlsdisorder": (None, None)})
        self.applied.clear()
        await c2.verify(self.net, "sni", self.applied.append)
        self.assertEqual(fake2.calls, [["none", "sni"], ["none", "tlsdisorder"]])
        self.assertEqual(self.applied, ["tlsdisorder"])

    async def test_nothing_works_reports_reason_and_keeps_method(self):
        c, _ = self.mk({"none": (R, R)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.FAILED)
        self.assertEqual(r["verdict"], probe.DPI_UNBEATEN)
        self.assertEqual(self.applied, [])

    async def test_dns_dead_does_not_run_full_test(self):
        c, fake = self.mk({"none": (D, D), "sni": (D, D)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["verdict"], probe.DNS_FAILED)
        self.assertEqual(len(fake.calls), 1)

    async def test_auto_off_never_switches(self):
        self.cfg["auto_method"] = False
        c, fake = self.mk({"none": (R, R), "sni": (R, R), "oob": (None, None)})
        r = await c.verify(self.net, "sni", self.applied.append)
        self.assertEqual(r["check"], checker.FAILED)
        self.assertEqual(self.applied, [])
        self.assertEqual(len(fake.calls), 1)

    async def test_result_for_old_network_is_not_saved(self):
        c, _ = self.mk({"none": (R, R), "sni": (R, R), "tlsdisorder": (None, None)})
        r = await c.verify(self.net, "sni", self.applied.append, still=lambda: False)
        self.assertEqual(r["check"], checker.FAILED)
        self.assertEqual(self.applied, [])
        self.assertEqual(checker.load_networks(self.path), {})

    async def test_custom_strategy_is_tested_and_never_replaced(self):
        c, fake = self.mk({"none": (R, R), "custom": (R, R), "oob": (None, None)})
        r = await c.verify(self.net, "custom", self.applied.append)
        self.assertEqual(r["check"], checker.FAILED)
        self.assertEqual(self.applied, [])
        self.assertEqual(fake.calls, [["none", "custom"]])
        c2, _ = self.mk({"none": (R, R), "custom": (None, R)})
        r2 = await c2.verify(self.net, "custom", self.applied.append)
        self.assertEqual(r2["check"], checker.WORKING)

    def test_networks_keyed_by_gateway_mac(self):
        a = netwatch.NetId("wifi:wlan0:192.168.1.1", "Wi-Fi", "aa:aa:aa:aa:aa:aa")
        b = netwatch.NetId("wifi:wlan0:192.168.1.1", "Wi-Fi", "bb:bb:bb:bb:bb:bb")
        c, _ = self.mk({})
        c._save(a, "oob")
        self.assertEqual(c.saved_for(a), "oob")
        self.assertIsNone(c.saved_for(b))

    def test_hostile_networks_file_never_crashes(self):
        for text in ('{"a":{"preset":[1]}}', "[" * 100000, '{"a": {"preset": {"x": 1}}}', "null", "\x00\x01"):
            with open(self.path, "w") as fh:
                fh.write(text)
            self.assertEqual(checker.load_networks(self.path), {})
        with open(self.path, "w") as fh:
            import json
            json.dump({f"k{i}": {"preset": "oob"} for i in range(1000)}, fh)
        self.assertLessEqual(len(checker.load_networks(self.path)), 256)

    def test_saved_networks_are_capped(self):
        c, _ = self.mk({})
        for i in range(300):
            c._save(netwatch.NetId(f"eth:eth0:10.0.{i // 250}.{i % 250}", "Ethernet"), "oob")
        self.assertEqual(len(c.networks), checker.MAX_NETWORKS)
        self.assertEqual(len(checker.load_networks(self.path)), checker.MAX_NETWORKS)

    def test_corrupt_networks_file_is_ignored(self):
        with open(self.path, "w") as fh:
            fh.write('{"a": {"preset": "rm -rf"}, "b": {"preset": "oob", "label": "x"}, "c": 5}')
        self.assertEqual(checker.load_networks(self.path), {"b": {"preset": "oob", "label": "x"}})


if __name__ == "__main__":
    unittest.main()
