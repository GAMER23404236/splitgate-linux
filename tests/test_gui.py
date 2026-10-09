"""GUI duman testi (başsız / offscreen). PyQt6 yoksa atlanır.

Ekran görüntüleri DPIGEC_SHOTS ortam değişkeniyle verilen klasöre kaydedilir.
"""
import json
import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from PyQt6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:  # pragma: no cover
    HAVE_QT = False


FAKE_STATUS = {
    "state": "running", "mode": "transparent", "preset": "sni", "version": "1.0.0",
    "check": "working", "check_detail": "4/4", "verdict": "works", "active_preset": "sni",
    "network": "Wi-Fi (wlan0)",
    "firewall": True, "doh": [{"name": "cloudflare", "ok": True}, {"name": "google", "ok": True}],
    "stats": {"uptime": 3725, "conn_total": 1523, "conn_active": 12, "tls_split": 1301,
              "http_split": 4, "passthrough": 218, "bytes_up": 12_345_678, "bytes_down": 987_654_321,
              "errors": 2, "dns_queries": 640, "dns_cached": 411, "dns_failed": 0, "doh_ok": 229,
              "doh_fail": 0, "last_error": "connection: TimeoutError"},
}

FAKE_PROBE = {"ok": True, "best": "sni", "results": [
    {"preset": "none", "label": "No splitting (baseline)", "ok": 0, "total": 4, "avg_ms": None,
     "domains": {"discord.com": {"ok": False, "err": "connection closed (EOF)"}}},
    {"preset": "sni", "label": "Split at SNI start", "ok": 4, "total": 4, "avg_ms": 212,
     "domains": {"discord.com": {"ok": True, "ms": 190}}},
    {"preset": "hafif", "label": "Light (single split)", "ok": 2, "total": 4, "avg_ms": 240,
     "domains": {"discord.com": {"ok": True, "ms": 240}}},
]}


@unittest.skipUnless(HAVE_QT, "PyQt6 kurulu değil")
class GuiSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from dpigec import i18n
        i18n.set_language("en")

    def tearDown(self):
        from dpigec import i18n
        i18n.set_language("en")

    def make_window(self):
        from dpigec.gui import app as gui
        self.app.setStyleSheet(gui.QSS)
        win = gui.MainWindow()
        win._timer.stop()
        return gui, win

    def test_window_and_form_roundtrip(self):
        gui, win = self.make_window()
        cfg = win._form_to_config()
        from dpigec import config
        self.assertEqual(cfg, config.normalize(win._base_cfg))

        # farklı bir yapılandırmayı forma yükle ve geri oku
        custom = config.normalize({
            "mode": "socks", "socks_port": 2080, "gateway": True,
            "strategy": {"preset": "custom", "positions": ["2", "sni"], "delay_ms": 7, "oob": True,
                         "http_host_case": True},
            "dns": {"providers": ["google", "cloudflare", "quad9"], "cache_seconds": 120},
            "ports": [80, 443, 8443], "quic_block": False,
            "domain_filter": {"mode": "include", "domains": ["discord.com", "x.com"]},
            "log_level": "debug",
        })
        win._load_form(custom)
        back = win._form_to_config()
        self.assertEqual(back["mode"], "socks")
        self.assertEqual(back["socks_port"], 2080)
        self.assertEqual(back["strategy"]["positions"], ["2", "sni"])
        self.assertEqual(back["strategy"]["delay_ms"], 7)
        self.assertTrue(back["strategy"]["oob"])
        self.assertEqual(back["dns"]["providers"][0], "google")
        self.assertEqual(back["ports"], [80, 443, 8443])
        self.assertEqual(back["domain_filter"]["domains"], ["discord.com", "x.com"])
        self.assertFalse(back["quic_block"])

        # ön ayar seçilince alanlar kilitlenir ve ön ayar değerlerini gösterir
        gui.set_combo(win.f_preset, "agresif")
        self.assertFalse(win.f_positions.isEnabled())
        self.assertIn("sniend", win.f_positions.text())
        win.close()

    def _wait(self, cond, seconds=3.0):
        import time
        end = time.monotonic() + seconds
        while not cond() and time.monotonic() < end:
            self.app.processEvents()
            time.sleep(0.01)
        self.app.processEvents()

    def test_quit_when_service_is_stopped_exits_without_asking_for_privileges(self):
        gui, win = self.make_window()
        calls = []
        old = gui.read_status, gui.run_ctl, gui.unit_active
        gui.unit_active = lambda: False
        gui.read_status = lambda: None
        gui.run_ctl = lambda args, stdin=None: calls.append(args) or {"ok": True}
        win._finish_quit = lambda: calls.append("quit")
        try:
            win._quit()
        finally:
            gui.read_status, gui.run_ctl, gui.unit_active = old
        self.assertEqual(calls, ["quit"])
        win.close()

    def test_quit_stops_the_running_service_then_exits(self):
        gui, win = self.make_window()
        calls = []
        old = gui.read_status, gui.run_ctl, gui.unit_active
        gui.unit_active = lambda: False
        gui.read_status = lambda: FAKE_STATUS
        gui.run_ctl = lambda args, stdin=None: calls.append(list(args)) or {"ok": True}
        win._finish_quit = lambda: calls.append("quit")
        try:
            win._quit()
            self._wait(lambda: "quit" in calls)
        finally:
            gui.read_status, gui.run_ctl, gui.unit_active = old
        self.assertEqual(calls, [["stop"], "quit"])
        win.close()

    def test_quit_stays_open_when_stopping_the_service_fails(self):
        gui, win = self.make_window()
        calls, warned = [], []
        old = gui.read_status, gui.run_ctl, gui.unit_active
        gui.unit_active = lambda: False
        gui.read_status = lambda: FAKE_STATUS
        gui.run_ctl = lambda args, stdin=None: calls.append(list(args)) or {"ok": False, "msg": "denied"}
        win._finish_quit = lambda: calls.append("quit")
        win._warn = lambda text, title="x": warned.append(text)
        try:
            win._quit()
            self._wait(lambda: warned)
        finally:
            gui.read_status, gui.run_ctl, gui.unit_active = old
        self.assertEqual(calls, [["stop"]])
        self.assertEqual(warned, ["denied"])
        self.assertIsNone(win._pending_target)
        win.close()

    def test_quit_stops_the_service_even_when_its_status_file_is_stale(self):
        gui, win = self.make_window()
        calls = []
        old = gui.read_status, gui.run_ctl, gui.unit_active
        gui.read_status = lambda: None
        gui.unit_active = lambda: True
        gui.run_ctl = lambda args, stdin=None: calls.append(list(args)) or {"ok": True}
        win._finish_quit = lambda: calls.append("quit")
        try:
            win._quit()
            self._wait(lambda: "quit" in calls)
        finally:
            gui.read_status, gui.run_ctl, gui.unit_active = old
        self.assertEqual(calls, [["stop"], "quit"])
        win.close()

    def test_quit_is_ignored_while_a_background_worker_runs(self):
        gui, win = self.make_window()
        called = []
        win._workers.append(object())
        win._finish_quit = lambda: called.append(1)
        win._quit()
        self.assertEqual(called, [])
        win._workers.clear()
        win.close()

    def test_finish_quit_really_quits_and_lets_the_window_close(self):
        gui, win = self.make_window()
        quit_calls = []
        old = gui.QApplication.quit
        gui.QApplication.quit = staticmethod(lambda: quit_calls.append(1))
        try:
            win._finish_quit()
        finally:
            gui.QApplication.quit = old
        self.assertEqual(quit_calls, [1])
        self.assertTrue(win._quitting)
        from PyQt6.QtGui import QCloseEvent
        ev = QCloseEvent()
        win.closeEvent(ev)
        self.assertTrue(ev.isAccepted())
        win.close()

    def test_quit_is_ignored_while_busy(self):
        gui, win = self.make_window()
        called = []
        win._busy = True
        win._finish_quit = lambda: called.append(1)
        win._quit()
        self.assertEqual(called, [])
        win._busy = False
        win.close()

    def test_brand_name_is_visible_in_the_header(self):
        gui, win = self.make_window()
        brands = [l for l in win.findChildren(gui.QLabel) if l.objectName() == "brand"]
        self.assertEqual([l.text() for l in brands], ["SplitGate"])
        self.assertEqual(win.windowTitle(), "SplitGate")
        win.close()

    def test_invalid_form_rejected(self):
        gui, win = self.make_window()
        from dpigec.config import ConfigError
        win.f_ports.setText("80, abc")
        with self.assertRaises((ConfigError, ValueError)):
            win._form_to_config()
        win.close()

    def test_status_rendering_and_screenshots(self):
        gui, win = self.make_window()
        win.render_status(None)
        self.assertEqual(win.state_label.text(), "Stopped")
        self.assertEqual(win.power.text(), "Start")
        win.render_status(FAKE_STATUS)
        self.assertEqual(win.state_label.text(), "Working")
        # Yeşil "Çalışıyor" yalnızca gerçek kontrol başarılıysa; servis açık olması yetmez.
        for check, text in (("idle", "Connected (not checked yet)"), ("checking", "Checking…"),
                            ("failed", "Not working on this network"),
                            ("not_blocked", "Connected, sites not blocked")):
            win.render_status(dict(FAKE_STATUS, check=check, verdict="ip_block"))
            self.assertEqual(win.state_label.text(), text)
        win.render_status(dict(FAKE_STATUS, check="failed", verdict="ip_block"))
        self.assertIn("IP block", win.state_detail.text())
        self.assertIn("Wi-Fi (wlan0)", win.state_detail.text())
        self.assertIn("f85149", win.state_label.styleSheet())
        win.render_status(dict(FAKE_STATUS, check="idle"))
        self.assertNotIn("2ea043", win.state_label.styleSheet())
        # Kapanırken eski "working" yeşili gösterilmez
        win.render_status(dict(FAKE_STATUS, state="stopping"))
        self.assertEqual(win.state_label.text(), "Stopping…")
        self.assertNotIn("2ea043", win.state_label.styleSheet())
        # Eski sürümün durum dosyasında "check" yok: yeşil olmaz
        old = {k: v for k, v in FAKE_STATUS.items() if k not in ("check", "check_detail", "verdict", "network")}
        win.render_status(old)
        self.assertEqual(win.state_label.text(), "Connected (not checked yet)")
        self.assertNotIn("2ea043", win.state_label.styleSheet())
        win.render_status(FAKE_STATUS)
        self.assertEqual(win.power.text(), "Stop")
        self.assertEqual(win.cards["conn"].value.text(), "12 / 1523")
        self.assertEqual(win.cards["uptime"].value.text(), "1h 02m")
        win._fill_probe_table(FAKE_PROBE)
        self.assertEqual(win.table.rowCount(), 3)
        self.assertTrue(win.apply_best.isEnabled())

        out = os.environ.get("DPIGEC_SHOTS")
        if out:
            os.makedirs(out, exist_ok=True)
            win.show()
            for i, name in enumerate(("durum", "ayarlar", "test", "gunluk", "hakkinda")):
                win.tabs.setCurrentIndex(i)
                self.app.processEvents()
                win.grab().save(os.path.join(out, f"{name}.png"))
        win.close()

    def test_language_switch_rebuilds_window_and_keeps_form(self):
        gui, win = self.make_window()
        win.render_status(None)
        self.assertEqual(win.power.text(), "Start")
        self.assertEqual(win.tabs.tabText(0), "Status")
        gui.set_combo(win.f_preset, "agresif")
        win.tabs.setCurrentIndex(2)
        from dpigec import i18n
        old_save, old_status = gui.save_language, gui.read_status
        saved = []
        gui.save_language = lambda code: saved.append(code) or True
        gui.read_status = lambda: None
        try:
            win._change_language("tr")
        finally:
            gui.save_language, gui.read_status = old_save, old_status
        self.assertEqual(saved, ["tr"])
        self.assertEqual(i18n.language(), "tr")
        self.assertEqual(win.power.text(), "Başlat")
        self.assertEqual(win.tabs.tabText(0), "Durum")
        self.assertEqual(win.tabs.currentIndex(), 2)
        self.assertEqual(win.f_preset.currentData(), "agresif")
        self.assertIn("Agresif", win.f_preset.currentText())
        win.render_status(FAKE_STATUS)
        self.assertEqual(win.state_label.text(), "Çalışıyor")
        self.assertEqual(win.cards["uptime"].value.text(), "1s 02dk")
        self.assertIn("Lisans: GPL-3.0-or-later", win.tabs.widget(4).findChild(gui.QLabel).text())
        win.close()

    def test_language_switch_is_refused_while_busy(self):
        gui, win = self.make_window()
        from dpigec import i18n
        win.render_status(None)
        win._busy = True
        win._change_language("tr")
        self.assertEqual(i18n.language(), "en")
        self.assertEqual(win.power.text(), "Start")
        win._busy = False
        win.close()

    def test_messages_from_helper_are_not_rendered_as_html(self):
        gui, win = self.make_window()
        from PyQt6.QtCore import Qt
        for label in (win.probe_msg, win.error_label, win.q_res):
            self.assertEqual(label.textFormat(), Qt.TextFormat.PlainText)
        win.close()

    def test_first_run_language_picker_returns_choice(self):
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QDialog, QPushButton
        from dpigec.gui import app as gui

        def click():
            for w in self.app.topLevelWidgets():
                if isinstance(w, QDialog) and w.isVisible():
                    [b for b in w.findChildren(QPushButton) if b.text() == "Türkçe"][0].click()

        QTimer.singleShot(200, click)
        self.assertEqual(gui.choose_language(), "tr")

    def test_first_run_language_picker_dismissed_returns_none(self):
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QDialog
        from dpigec.gui import app as gui

        def close():
            for w in self.app.topLevelWidgets():
                if isinstance(w, QDialog) and w.isVisible():
                    w.reject()

        QTimer.singleShot(200, close)
        self.assertIsNone(gui.choose_language())

    def test_gui_module_has_no_stale_status_when_no_engine(self):
        from dpigec.status import read_status
        self.assertIsNone(read_status("/nonexistent/status.json"))


if __name__ == "__main__":
    unittest.main()
