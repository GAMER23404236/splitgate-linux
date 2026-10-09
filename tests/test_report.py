"""Sorun raporu: içerik, gizlilik süzgeci, mailto."""
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dpigec import config, report  # noqa: E402

LOG = [
    "08:00:01 INFO dpigec: SplitGate 1.1.0 running (mode=transparent, strategy=sni 1,sni)",
    "08:00:02 DEBUG dpigec.relay: splitting secret-site.example: tls, split @1,153, 3 pieces",
    "08:00:03 DEBUG dpigec.relay: upstream error (secret-site.example): ConnectionResetError()",
    "08:00:04 INFO dpigec: network changed: Wi-Fi (wlan0) -> Ethernet (eth0), reset 3 connections",
    "08:00:09 INFO dpigec: check: TLS + disorder opens 4/4 sites on Ethernet (eth0)",
    "08:00:10 WARNING dpigec.doh: provider quad9 is down",
]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.default_config()
        self.status = {
            "state": "running", "network": "Ethernet (eth0)", "check": "working", "check_detail": "4/4",
            "verdict": "works", "active_preset": "tlsdisorder",
            "stats": {"bytes_up": 10, "bytes_down": 20, "uptime": 5, "conn_active": 1, "conn_total": 2},
            "check_results": [{"preset": "tlsdisorder", "label": "TLS + disorder", "ok": 1, "total": 1,
                               "avg_ms": 600, "domains": {"discord.com": {"ok": True, "ms": 600}}}],
        }

    def test_note_first_and_sections(self):
        text = report.build(self.cfg, self.status, "Discord açılmıyor, Türk Telekom", LOG)
        self.assertLess(text.index("Discord açılmıyor"), text.index("Version:"))
        for part in ("Check: working 4/4", "Traffic: up 10 B", "TLS + disorder", "discord.com: ok 600 ms",
                     "network changed", "check: TLS + disorder opens", "provider quad9 is down"):
            self.assertIn(part, text)

    def test_visited_sites_are_not_in_report(self):
        text = report.build(self.cfg, self.status, "", LOG)
        self.assertNotIn("secret-site.example", text)
        self.assertIn("(not filled in)", text)

    def test_traceback_and_connection_logger_lines_are_dropped(self):
        log = [
            "08:00:01 INFO dpigec: SplitGate 1.1.0 running (mode=transparent, strategy=sni 1,sni)",
            "08:00:02 ERROR dpigec.relay: client error for secret-site.example",
            "Traceback (most recent call last):",
            "OSError: could not connect to secret-site.example",
            "08:00:03 WARNING dpigec.doh: provider quad9 is down",
        ]
        text = report.build(self.cfg, self.status, "", log)
        self.assertNotIn("secret-site.example", text)
        self.assertNotIn("Traceback", text)
        self.assertIn("provider quad9 is down", text)

    def test_not_running(self):
        self.assertIn("Service: not running", report.build(self.cfg, None))

    def test_mailto(self):
        url = report.mailto("a b\nç", "SplitGate report")
        self.assertTrue(url.startswith("mailto:gmtr244@gmail.com?"))
        q = urllib.parse.parse_qs(url.split("?", 1)[1])
        self.assertEqual(q["body"], ["a b\nç"])
        self.assertEqual(q["subject"], ["SplitGate report"])
        self.assertLessEqual(len(urllib.parse.parse_qs(report.mailto("x" * 9000, "s").split("?", 1)[1])["body"][0]), 6000)


if __name__ == "__main__":
    unittest.main()
