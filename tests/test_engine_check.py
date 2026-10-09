"""Motor: ağ değişimi, gerçek kontrol sonucu ve canlı yöntem değişimi (ağa çıkmaz)."""
import asyncio
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import checker, config, engine, netwatch  # noqa: E402

A = netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)")
B = netwatch.NetId("eth:eth0:192.168.1.1", "Ethernet (eth0)")


class FakeChecker:
    def __init__(self, result, delay=0.0, switch_to=None):
        self.result, self.delay, self.switch_to = result, delay, switch_to
        self.calls = []
        self.nets = []

    async def verify(self, net, active, apply, still=lambda: True):
        self.calls.append((net.key, active))
        self.nets.append(net)
        await asyncio.sleep(self.delay)
        if self.switch_to:
            apply(self.switch_to)
        return dict(self.result, preset=self.switch_to or active)


def make_engine(fake):
    tmp = tempfile.mkdtemp()
    e = engine.Engine(config.default_config(), status_path=os.path.join(tmp, "status.json"),
                      manage_firewall=False)
    e.state = "running"
    e.relay = mock.Mock()
    e.relay.reset_connections.return_value = 3
    e.doh = mock.Mock()
    e.doh.health.return_value = []
    e.resolver = mock.Mock()
    e.dns = mock.Mock()
    e.checker = fake
    return e


WORK = {"check": checker.WORKING, "detail": "2/2", "verdict": "works", "results": []}
FAIL = {"check": checker.FAILED, "detail": "", "verdict": "dpi_unbeaten", "results": []}


class EngineCheckTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.sleep = mock.patch.object(engine.asyncio, "sleep", side_effect=self._fast_sleep)
        self._real_sleep = asyncio.sleep
        self.sleep.start()

    async def asyncTearDown(self):
        self.sleep.stop()

    async def _fast_sleep(self, t):
        await self._real_sleep(0)

    async def test_first_network_checks_without_reset(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(A)
        self.assertEqual(e.check, checker.CHECKING)
        await e._check_task
        e.relay.reset_connections.assert_not_called()
        self.assertEqual((e.check, e.check_detail), (checker.WORKING, "2/2"))

    async def test_switch_resets_connections_and_caches_then_rechecks(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(A)
        await e._check_task
        e._on_network(B)
        e.relay.reset_connections.assert_called_once()
        e.doh.close.assert_called()
        e.resolver.flush.assert_called()
        e.dns.flush.assert_called()
        await e._check_task
        self.assertEqual(e.checker.calls[-1][0], B.key)

    async def test_stale_result_is_dropped(self):
        slow = FakeChecker(WORK, delay=0.05, switch_to="oob")
        e = make_engine(slow)
        e._on_network(A)
        task = e._check_task
        await self._real_sleep(0)
        e.checker = FakeChecker(FAIL)
        e._on_network(B)
        with self.assertRaises(asyncio.CancelledError):
            await task
        await e._check_task
        self.assertEqual(e.check, checker.FAILED)
        self.assertNotEqual(e.active_preset, "oob")

    async def test_working_method_is_applied_live(self):
        e = make_engine(FakeChecker(WORK, switch_to="tlsdisorder"))
        e.network = None
        e._on_network(A)
        await e._check_task
        self.assertEqual(e.active_preset, "tlsdisorder")
        st = e.relay.set_strategy.call_args[0][0]
        self.assertTrue(st["tlsrec"] and st["disorder"])

    async def test_back_from_no_network_resets_connections(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(A)
        await e._check_task
        e._on_network(None)
        e.relay.reset_connections.reset_mock()
        e._on_network(A)
        e.relay.reset_connections.assert_called_once()
        await e._check_task

    async def test_old_results_cleared_on_change(self):
        e = make_engine(FakeChecker(dict(WORK, results=[{"preset": "x"}])))
        e._on_network(A)
        await e._check_task
        self.assertTrue(e.check_results)
        e._on_network(B)
        self.assertEqual(e.check_results, [])
        await e._check_task

    async def test_same_gateway_other_mac_is_other_network(self):
        e = make_engine(FakeChecker(WORK))
        home = netwatch.NetId("wifi:wlan0:192.168.1.1", "Wi-Fi (wlan0)", "aa:aa:aa:aa:aa:aa")
        cafe = netwatch.NetId("wifi:wlan0:192.168.1.1", "Wi-Fi (wlan0)", "bb:bb:bb:bb:bb:bb")
        e._on_network(home)
        await e._check_task
        e._on_network(cafe)
        e.relay.reset_connections.assert_called_once()
        await e._check_task

    async def test_mac_learned_later_is_not_a_change(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)", ""))
        await e._check_task
        e._on_network(netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)", "aa:aa:aa:aa:aa:aa"))
        e.relay.reset_connections.assert_not_called()
        self.assertEqual(e.network.mac, "aa:aa:aa:aa:aa:aa")

    async def test_late_arp_entry_is_used_for_checking_and_saving(self):
        fake = FakeChecker(WORK)
        e = make_engine(fake)
        e._on_network(netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)", ""))
        learned = netwatch.NetId("wifi:wlan0:10.0.0.1", "Wi-Fi (wlan0)", "aa:aa:aa:aa:aa:aa")
        with mock.patch.object(netwatch, "current", return_value=learned):
            await e._check_task
        self.assertEqual(fake.nets[-1].mac, "aa:aa:aa:aa:aa:aa")
        self.assertEqual(e.network.mac, "aa:aa:aa:aa:aa:aa")

    async def test_watch_loop_survives_errors(self):
        e = make_engine(FakeChecker(WORK))
        calls = []

        def boom():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("x")
            e._stop.set()
            return A
        with mock.patch.object(netwatch, "current", boom):
            await asyncio.wait_for(e._net_loop(), 5)
        self.assertGreaterEqual(len(calls), 2)

    async def test_network_lost_clears_status(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(A)
        await e._check_task
        e._on_network(None)
        self.assertEqual((e.check, e.check_detail, e.verdict), (checker.IDLE, "", ""))

    async def test_status_contains_check(self):
        e = make_engine(FakeChecker(WORK))
        e._on_network(A)
        await e._check_task
        e._publish()
        from dpigec.status import read_status
        st = read_status(e.status_path)
        self.assertEqual((st["check"], st["network"], st["check_detail"]), ("working", "Wi-Fi (wlan0)", "2/2"))


if __name__ == "__main__":
    unittest.main()
