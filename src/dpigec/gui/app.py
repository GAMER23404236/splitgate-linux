# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""SplitGate ana penceresi (PyQt6)."""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFormLayout, QFrame,
                             QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu,
                             QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox,
                             QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTabWidget,
                             QVBoxLayout, QWidget, QHeaderView, QAbstractItemView)

from .. import __version__
from ..i18n import (DEFAULT_LANGUAGE, LANGUAGES, _, init as init_language, language,
                    normalize_language, save_language, saved_language, set_language)
from ..config import (LOG_FILE, PRESETS, SYSTEM_CONFIG, ConfigError, default_config, load_config,
                      normalize)
from ..ctlclient import run_ctl, unit_active, unit_enabled
from ..probe import diagnose, verdict_text
from . import single
from ..status import read_status

GREEN, GREY, AMBER, RED = "#2ea043", "#6e7681", "#d29922", "#f85149"
ICON_PATH = Path(__file__).parent / "resources" / "dpigec.svg"

MODE_ITEMS = [("transparent", "System-wide (transparent, recommended)"),
              ("socks", "Local SOCKS5/HTTP proxy (127.0.0.1)")]
FILTER_ITEMS = [("all", "All sites"), ("include", "Only listed sites"),
                ("exclude", "All except listed")]
DNS_ITEMS = [("cloudflare", "Cloudflare (1.1.1.1)"), ("google", "Google (8.8.8.8)"),
             ("quad9", "Quad9 (9.9.9.9)"), ("custom", "Custom provider")]
LOG_LEVELS = [("info", "Info"), ("debug", "Verbose (debug)"), ("warning", "Warning"),
              ("error", "Errors only")]

QSS = """
QFrame#card { border: 1px solid palette(mid); border-radius: 10px; }
QLabel#cardValue { font-size: 20px; font-weight: 600; }
QLabel#cardTitle { color: palette(placeholder-text); font-size: 11px; }
QPushButton#power { font-size: 16px; font-weight: 600; padding: 14px 34px; border-radius: 12px;
                    color: white; }
QPushButton#primary { font-weight: 600; padding: 7px 18px; }
QLabel#hero { font-size: 22px; font-weight: 700; }
QLabel#brand { font-size: 12px; font-weight: 700; color: palette(placeholder-text); }
QLabel#muted { color: palette(placeholder-text); }
"""


def app_icon() -> QIcon:
    icon = QIcon(str(ICON_PATH)) if ICON_PATH.exists() else QIcon()
    if icon.isNull():  # SVG eklentisi yoksa basit bir simge çiz
        pm = QPixmap(128, 128)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor("#2563eb"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(14, 8, 100, 112, 28, 28)
        p.setPen(QColor("white"))
        f = QFont()
        f.setBold(True)
        f.setPixelSize(44)
        p.setFont(f)
        p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "DPI")
        p.end()
        icon = QIcon(pm)
    return icon


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def check_style(check: str):
    """Ana durum rengi ve metni: yalnızca gerçek kontrol başarılıysa yeşil "Çalışıyor"."""
    if check == "working":
        return GREEN, _("Working")
    if check == "not_blocked":
        return GREEN, _("Connected, sites not blocked")
    if check == "failed":
        return RED, _("Not working on this network")
    if check == "checking":
        return AMBER, _("Checking…")
    return AMBER, _("Connected (not checked yet)")


def fmt_duration(sec: int) -> str:
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    return _("{h}h {m:02d}m", h=h, m=m) if h else _("{m}m {s:02d}s", m=m, s=s)


def combo_with(items) -> QComboBox:
    c = QComboBox()
    for data, label in items:
        c.addItem(_(label), data)
    return c


def set_combo(c: QComboBox, data) -> None:
    i = c.findData(data)
    if i >= 0:
        c.setCurrentIndex(i)


# --------------------------------------------------------------------------
# Arka plan işçileri
# --------------------------------------------------------------------------
class CtlWorker(QThread):
    done = pyqtSignal(dict)

    def __init__(self, args: List[str], stdin_text: Optional[str] = None, parent=None) -> None:
        super().__init__(parent)
        self.args, self.stdin_text = args, stdin_text

    def run(self) -> None:
        self.done.emit(run_ctl(self.args, self.stdin_text))


class QuickTestWorker(QThread):
    done = pyqtSignal(dict)

    def __init__(self, host: str, parent=None) -> None:
        super().__init__(parent)
        self.host = host

    def run(self) -> None:
        t0 = time.monotonic()
        try:
            with socket.create_connection((self.host, 443), timeout=8) as raw:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    ver = tls.version()
            self.done.emit({"ok": True, "ms": int((time.monotonic() - t0) * 1000), "tls": ver})
        except Exception as e:  # noqa: BLE001
            self.done.emit({"ok": False, "err": f"{type(e).__name__}: {e}"})


class Card(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)
        self.value = QLabel("–")
        self.value.setObjectName("cardValue")
        t = QLabel(title)
        t.setObjectName("cardTitle")
        lay.addWidget(self.value)
        lay.addWidget(t)

    def set(self, text: str) -> None:
        self.value.setText(text)


# --------------------------------------------------------------------------
# Ana pencere
# --------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SplitGate")
        self.setWindowIcon(app_icon())
        self.resize(820, 680)
        self._workers: List[QThread] = []
        self._busy = False
        self._pending_since = 0.0
        self._pending_target: Optional[bool] = None
        self._status: Optional[Dict[str, Any]] = None
        self._last_probe: Optional[Dict[str, Any]] = None
        self._quitting = False
        self._custom_cache = {"positions": "1, midsld", "delay": 1, "oob": False}

        self._build_ui()
        self._build_tray()
        self._load_form(self._read_config())
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._tick_count = 0
        self._tick()

    # ---- iskelet -----------------------------------------------------------
    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(18, 14, 18, 8)
        lay.addLayout(self._build_header())
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_status_tab(), _("Status"))
        self.tabs.addTab(self._build_settings_tab(), _("Settings"))
        self.tabs.addTab(self._build_test_tab(), _("Test"))
        self.tabs.addTab(self._build_log_tab(), _("Log"))
        self.tabs.addTab(self._build_about_tab(), _("About"))
        self.tabs.currentChanged.connect(lambda _i: self._refresh_log())
        self.statusBar().showMessage(_("Ready"))

    def _warn(self, text: str, title: str = "SplitGate") -> None:
        box = QMessageBox(QMessageBox.Icon.Warning, title, text, QMessageBox.StandardButton.Ok, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def _change_language(self, code: str) -> None:
        if code == language():
            return
        if self._busy or self._workers:
            self.statusBar().showMessage(_("Please wait for the current operation to finish."), 5000)
            return
        set_language(code)
        saved = save_language(code)
        try:
            cfg = self._form_to_config()
        except (ConfigError, ValueError):
            cfg = self._base_cfg
        index = self.tabs.currentIndex()
        self._build_ui()
        self._load_form(cfg)
        self.tabs.setCurrentIndex(index)
        self._retranslate_tray()
        self._tick()
        self._refresh_log()
        if not saved:
            self.statusBar().showMessage(_("could not save the language choice"), 8000)

    def _build_header(self) -> QHBoxLayout:
        h = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(app_icon().pixmap(56, 56))
        h.addWidget(icon)
        col = QVBoxLayout()
        col.setSpacing(0)
        brand = QLabel("SplitGate")
        brand.setObjectName("brand")
        col.addWidget(brand)
        self.state_label = QLabel(_("Stopped"))
        self.state_label.setObjectName("hero")
        self.state_detail = QLabel("")
        self.state_detail.setObjectName("muted")
        col.addWidget(self.state_label)
        col.addWidget(self.state_detail)
        h.addLayout(col, 1)
        self.lang_btn = QPushButton("🌐 " + LANGUAGES[language()])
        lang_menu = QMenu(self.lang_btn)
        for code, name in LANGUAGES.items():
            act = lang_menu.addAction(name)
            act.triggered.connect(lambda _checked=False, c=code: self._change_language(c))
        self.lang_btn.setMenu(lang_menu)
        h.addWidget(self.lang_btn)
        self.power = QPushButton(_("Start"))
        self.power.setObjectName("power")
        self.power.setCursor(Qt.CursorShape.PointingHandCursor)
        self.power.clicked.connect(self._toggle)
        h.addWidget(self.power)
        return h

    def _build_status_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.cards = {
            "conn": Card(_("Active / total connections")), "split": Card(_("Split TLS / HTTP")),
            "pass": Card(_("Passed through")), "traffic": Card(_("Traffic ↑ / ↓")),
            "dns": Card(_("DNS queries (DoH)")), "cache": Card(_("DNS from cache")),
            "uptime": Card(_("Uptime")), "err": Card(_("Error count")),
        }
        for i, c in enumerate(self.cards.values()):
            grid.addWidget(c, i // 4, i % 4)
        lay.addLayout(grid)
        self.doh_label = QLabel("")
        self.doh_label.setObjectName("muted")
        lay.addWidget(self.doh_label)
        self.error_label = QLabel("")
        self.error_label.setTextFormat(Qt.TextFormat.PlainText)
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color: {RED};")
        lay.addWidget(self.error_label)
        box = QGroupBox(_("Startup"))
        bl = QVBoxLayout(box)
        self.autostart = QCheckBox(_("Start automatically at boot"))
        self.autostart.clicked.connect(self._autostart_clicked)
        bl.addWidget(self.autostart)
        note = QLabel(_("The service runs at the system level. Closing this window does not stop it; "
                        "use the button above, or Quit in the tray menu, to stop it."))
        note.setObjectName("muted")
        note.setWordWrap(True)
        bl.addWidget(note)
        lay.addWidget(box)
        lay.addStretch(1)
        return w

    def _build_settings_tab(self) -> QWidget:
        outer = QWidget()
        ol = QVBoxLayout(outer)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        lay = QVBoxLayout(inner)

        # Çalışma modu
        g = QGroupBox(_("Operating mode"))
        f = QFormLayout(g)
        self.f_mode = combo_with(MODE_ITEMS)
        self.f_mode.currentIndexChanged.connect(self._update_enabled)
        self.f_socks_port = QSpinBox()
        self.f_socks_port.setRange(1024, 65535)
        self.f_gateway = QCheckBox(_("Also process traffic passing through this computer (shared)"))
        self.f_ipv6 = QCheckBox(_("Use IPv6"))
        f.addRow(_("Mode"), self.f_mode)
        f.addRow(_("SOCKS5/HTTP port"), self.f_socks_port)
        f.addRow("", self.f_gateway)
        f.addRow("", self.f_ipv6)
        lay.addWidget(g)

        # Strateji
        g = QGroupBox(_("Splitting strategy"))
        f = QFormLayout(g)
        self.f_preset = QComboBox()
        for key, p in PRESETS.items():
            self.f_preset.addItem(_(p["label"]), key)
        self.f_preset.addItem(_("Custom"), "custom")
        self.f_preset.currentIndexChanged.connect(self._preset_changed)
        self.f_positions = QLineEdit()
        self.f_positions.setPlaceholderText(_("e.g. 1,midsld  (number, sni, midsld, sniend, host, method)"))
        self.f_delay = QSpinBox()
        self.f_delay.setRange(0, 200)
        self.f_delay.setSuffix(" ms")
        self.f_oob = QCheckBox(_("Send an OOB byte after the first piece (experimental)"))
        self.f_hostcase = QCheckBox(_("Mix the letter case of the HTTP 'Host:' header"))
        self.f_httpsplit = QCheckBox(_("Also split plain HTTP requests"))
        f.addRow(_("Preset"), self.f_preset)
        f.addRow(_("Split positions"), self.f_positions)
        f.addRow(_("Delay between pieces"), self.f_delay)
        f.addRow("", self.f_oob)
        f.addRow("", self.f_hostcase)
        f.addRow("", self.f_httpsplit)
        lay.addWidget(g)

        # DNS
        g = QGroupBox(_("DNS (DoH against DNS poisoning)"))
        f = QFormLayout(g)
        self.f_dns_on = QCheckBox(_("Resolve DNS queries over encrypted DoH"))
        self.f_dns_on.clicked.connect(self._update_enabled)
        self.f_dns_primary = combo_with(DNS_ITEMS)
        self.f_dns_primary.currentIndexChanged.connect(self._update_enabled)
        self.f_dns_host = QLineEdit()
        self.f_dns_host.setPlaceholderText(_("dns.example.net"))
        self.f_dns_ips = QLineEdit()
        self.f_dns_ips.setPlaceholderText("9.9.9.10, 149.112.112.10")
        self.f_dns_path = QLineEdit("/dns-query")
        self.f_dns_cache = QSpinBox()
        self.f_dns_cache.setRange(0, 86400)
        self.f_dns_cache.setSuffix(_(" s"))
        f.addRow("", self.f_dns_on)
        f.addRow(_("Primary provider"), self.f_dns_primary)
        f.addRow(_("Custom: host"), self.f_dns_host)
        f.addRow(_("Custom: IP addresses"), self.f_dns_ips)
        f.addRow(_("Custom: path"), self.f_dns_path)
        f.addRow(_("Cache duration (upper limit)"), self.f_dns_cache)
        lay.addWidget(g)

        # Trafik
        g = QGroupBox(_("Traffic"))
        f = QFormLayout(g)
        self.f_ports = QLineEdit()
        self.f_ports.setPlaceholderText("80, 443")
        self.f_quic = QCheckBox(_("Block QUIC/HTTP3 (browsers fall back to TCP; required for splitting)"))
        self.f_filter = combo_with(FILTER_ITEMS)
        self.f_filter.currentIndexChanged.connect(self._update_enabled)
        self.f_domains = QPlainTextEdit()
        self.f_domains.setPlaceholderText(_("One domain per line (e.g. discord.com)"))
        self.f_domains.setFixedHeight(80)
        f.addRow(_("Ports to redirect"), self.f_ports)
        f.addRow("", self.f_quic)
        f.addRow(_("Sites to apply splitting to"), self.f_filter)
        f.addRow(_("Domain list"), self.f_domains)
        lay.addWidget(g)

        # Günlük
        g = QGroupBox(_("Log"))
        f = QFormLayout(g)
        self.f_loglevel = combo_with(LOG_LEVELS)
        self.f_logdomains = QCheckBox(_("Write visited domain names to the log (privacy risk)"))
        f.addRow(_("Detail level"), self.f_loglevel)
        f.addRow("", self.f_logdomains)
        lay.addWidget(g)
        lay.addStretch(1)
        scroll.setWidget(inner)
        ol.addWidget(scroll, 1)

        row = QHBoxLayout()
        reset = QPushButton(_("Reset to defaults"))
        reset.clicked.connect(lambda: self._load_form(default_config()))
        self.save_btn = QPushButton(_("Save and apply"))
        self.save_btn.setObjectName("primary")
        self.save_btn.clicked.connect(self._save)
        row.addWidget(reset)
        row.addStretch(1)
        row.addWidget(self.save_btn)
        ol.addLayout(row)
        return outer

    def _build_test_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        g = QGroupBox(_("Automatic strategy finder"))
        gl = QVBoxLayout(g)
        info = QLabel(_("Each strategy is tried on the sites below with a real TLS handshake. "
                        "The result does not depend on system DNS (DoH is used). "
                        "An administrator password is requested."))
        info.setWordWrap(True)
        info.setObjectName("muted")
        gl.addWidget(info)
        self.t_domains = QLineEdit()
        self.t_domains.setPlaceholderText("discord.com, x.com, roblox.com")
        gl.addWidget(self.t_domains)
        row = QHBoxLayout()
        self.probe_btn = QPushButton(_("Try strategies"))
        self.probe_btn.setObjectName("primary")
        self.probe_btn.clicked.connect(self._probe)
        self.apply_best = QPushButton(_("Apply recommended"))
        self.apply_best.setEnabled(False)
        self.apply_best.clicked.connect(self._apply_best)
        row.addWidget(self.probe_btn)
        row.addWidget(self.apply_best)
        row.addStretch(1)
        gl.addLayout(row)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([_("Strategy"), _("Sites opened"), _("Avg. time")])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        gl.addWidget(self.table, 1)
        self.probe_msg = QLabel("")
        self.probe_msg.setTextFormat(Qt.TextFormat.PlainText)
        self.probe_msg.setWordWrap(True)
        gl.addWidget(self.probe_msg)
        lay.addWidget(g, 1)

        g = QGroupBox(_("Quick connection test (through the system)"))
        gl = QHBoxLayout(g)
        self.q_host = QLineEdit("discord.com")
        self.q_btn = QPushButton(_("Try"))
        self.q_btn.clicked.connect(self._quick_test)
        self.q_res = QLabel("")
        self.q_res.setTextFormat(Qt.TextFormat.PlainText)
        gl.addWidget(self.q_host, 1)
        gl.addWidget(self.q_btn)
        gl.addWidget(self.q_res, 2)
        lay.addWidget(g)
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.log_view.setFont(mono)
        lay.addWidget(self.log_view, 1)
        row = QHBoxLayout()
        copy = QPushButton(_("Copy"))
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.log_view.toPlainText()))
        row.addStretch(1)
        row.addWidget(copy)
        lay.addLayout(row)
        return w

    def _build_about_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        t = QLabel(_(
            "<h2>SplitGate {version}</h2>"
            "<p>A DPI bypass tool for Linux with a GUI, written from scratch.</p>"
            "<ul>"
            "<li>Splits the TLS ClientHello at the SNI; splits the Host header in plain HTTP.</li>"
            "<li>Gets around DNS poisoning with DoH (Cloudflare / Google / Quad9).</li>"
            "<li>Works on all Wi-Fi and wired connections through nftables; "
            "it can also be used only as a local SOCKS5 proxy.</li>"
            "<li>Content is never decrypted; your traffic does not pass through any third-party server.</li></ul>"
            "<p>This tool is only meant to get around access blocks; it is not a VPN and does not "
            "hide your IP address. You are responsible for how you use it.</p>"
            "<p>© 2026 Project Gamers — License: GPL-3.0-or-later</p>", version=__version__))
        t.setTextFormat(Qt.TextFormat.RichText)
        t.setWordWrap(True)
        t.setAlignment(Qt.AlignmentFlag.AlignTop)
        lay.addWidget(t)
        lay.addStretch(1)
        return w

    # ---- tepsi -------------------------------------------------------------
    def _build_tray(self) -> None:
        self.tray: Optional[QSystemTrayIcon] = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu()
        self._tray_show = QAction(_("Show window"), self)
        self._tray_show.triggered.connect(self._show_window)
        self.tray_toggle = QAction(_("Start"), self)
        self.tray_toggle.triggered.connect(self._toggle)
        self._tray_quit = QAction(_("Quit"), self)
        self._tray_quit.triggered.connect(self._quit)
        menu.addAction(self._tray_show)
        menu.addAction(self.tray_toggle)
        menu.addSeparator()
        menu.addAction(self._tray_quit)
        self._tray_menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self._show_window()
            if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def _retranslate_tray(self) -> None:
        if self.tray is None:
            return
        self._tray_show.setText(_("Show window"))
        self._tray_quit.setText(_("Quit"))

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit(self) -> None:
        if self._busy or self._workers:
            self.statusBar().showMessage(_("Please wait for the current operation to finish."), 5000)
            return
        if read_status() is None and unit_active() is not True:
            self._finish_quit()
            return

        def done(res: Dict[str, Any]) -> None:
            if res.get("ok"):
                self._finish_quit()
            else:
                self._pending_target = None
                self._warn(res.get("msg", _("Operation failed")))

        self._pending_target = False
        self._pending_since = time.monotonic()
        self._run(["stop"], None, done, _("Stopping…"))

    def _finish_quit(self) -> None:
        self._quitting = True
        QApplication.quit()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.tray is not None and self.tray.isVisible() and not self._quitting:
            self.hide()
            event.ignore()
        else:
            event.accept()

    # ---- yapılandırma <-> form --------------------------------------------
    @staticmethod
    def _read_config() -> Dict[str, Any]:
        try:
            return load_config(SYSTEM_CONFIG)
        except ConfigError:
            return default_config()

    def _load_form(self, cfg: Dict[str, Any]) -> None:
        cfg = normalize(cfg)
        st, dns = cfg["strategy"], cfg["dns"]
        set_combo(self.f_mode, cfg["mode"])
        self.f_socks_port.setValue(cfg["socks_port"])
        self.f_gateway.setChecked(cfg["gateway"])
        self.f_ipv6.setChecked(cfg["ipv6"])
        self._custom_cache = {"positions": ", ".join(st["positions"]), "delay": st["delay_ms"],
                              "oob": st["oob"]}
        set_combo(self.f_preset, st["preset"])
        self._preset_changed()
        self.f_hostcase.setChecked(st["http_host_case"])
        self.f_httpsplit.setChecked(st["http_split"])
        self.f_dns_on.setChecked(dns["enabled"])
        set_combo(self.f_dns_primary, dns["providers"][0])
        self.f_dns_host.setText(dns["custom"]["host"])
        self.f_dns_ips.setText(", ".join(dns["custom"]["ips"]))
        self.f_dns_path.setText(dns["custom"]["path"])
        self.f_dns_cache.setValue(dns["cache_seconds"])
        self.f_ports.setText(", ".join(str(p) for p in cfg["ports"]))
        self.f_quic.setChecked(cfg["quic_block"])
        set_combo(self.f_filter, cfg["domain_filter"]["mode"])
        self.f_domains.setPlainText("\n".join(cfg["domain_filter"]["domains"]))
        set_combo(self.f_loglevel, cfg["log_level"])
        self.f_logdomains.setChecked(cfg["log_domains"])
        self.t_domains.setText(", ".join(cfg["probe_domains"]))
        self._base_cfg = cfg
        self._update_enabled()

    def _preset_changed(self) -> None:
        key = self.f_preset.currentData()
        custom = key == "custom"
        if custom:
            c = self._custom_cache
            self.f_positions.setText(c["positions"])
            self.f_delay.setValue(c["delay"])
            self.f_oob.setChecked(c["oob"])
        else:
            p = PRESETS[key]
            self.f_positions.setText(", ".join(p["positions"]))
            self.f_delay.setValue(p["delay_ms"])
            self.f_oob.setChecked(p["oob"])
        for wdg in (self.f_positions, self.f_delay, self.f_oob):
            wdg.setEnabled(custom)

    def _update_enabled(self) -> None:
        socks = self.f_mode.currentData() == "socks"
        self.f_socks_port.setEnabled(socks)
        dns_on = self.f_dns_on.isChecked()
        self.f_dns_primary.setEnabled(True)
        custom_dns = self.f_dns_primary.currentData() == "custom"
        for wdg in (self.f_dns_host, self.f_dns_ips, self.f_dns_path):
            wdg.setEnabled(custom_dns)
        self.f_dns_cache.setEnabled(dns_on)
        self.f_domains.setEnabled(self.f_filter.currentData() != "all")

    @staticmethod
    def _split_list(text: str) -> List[str]:
        return [t for t in text.replace(",", " ").replace(";", " ").split() if t]

    def _form_to_config(self) -> Dict[str, Any]:
        base = json.loads(json.dumps(self._base_cfg))  # derin kopya
        primary = self.f_dns_primary.currentData()
        order = [primary] + [p for p in ("cloudflare", "google", "quad9") if p != primary]
        base.update({
            "mode": self.f_mode.currentData(),
            "socks_port": self.f_socks_port.value(),
            "gateway": self.f_gateway.isChecked(),
            "ipv6": self.f_ipv6.isChecked(),
            "ports": [int(p) for p in self._split_list(self.f_ports.text())],
            "quic_block": self.f_quic.isChecked(),
            "log_level": self.f_loglevel.currentData(),
            "log_domains": self.f_logdomains.isChecked(),
            "probe_domains": self._split_list(self.t_domains.text()) or base["probe_domains"],
        })
        base["strategy"].update({
            "preset": self.f_preset.currentData(),
            "http_host_case": self.f_hostcase.isChecked(),
            "http_split": self.f_httpsplit.isChecked(),
        })
        if self.f_preset.currentData() == "custom":
            base["strategy"].update({
                "positions": self._split_list(self.f_positions.text()),
                "delay_ms": self.f_delay.value(),
                "oob": self.f_oob.isChecked(),
            })
        base["dns"].update({
            "enabled": self.f_dns_on.isChecked(),
            "providers": order,
            "cache_seconds": self.f_dns_cache.value(),
            "custom": {"host": self.f_dns_host.text().strip(),
                       "ips": self._split_list(self.f_dns_ips.text()),
                       "path": self.f_dns_path.text().strip() or "/dns-query"},
        })
        base["domain_filter"] = {"mode": self.f_filter.currentData(),
                                 "domains": [d for d in self.f_domains.toPlainText().splitlines() if d.strip()]}
        return normalize(base)

    # ---- komutlar ----------------------------------------------------------
    def _run(self, args: List[str], stdin_text: Optional[str], done: Callable[[Dict[str, Any]], None],
             busy_msg: str) -> None:
        if self._busy:
            return
        self._busy = True
        self.statusBar().showMessage(busy_msg)
        self._update_buttons()
        worker = CtlWorker(args, stdin_text, self)
        self._workers.append(worker)

        def finished(res: Dict[str, Any]) -> None:
            self._busy = False
            if worker in self._workers:
                self._workers.remove(worker)
            self.statusBar().showMessage(res.get("msg", "") or _("Ready"), 8000)
            self._update_buttons()
            done(res)

        worker.done.connect(finished)
        worker.start()

    def _toggle(self) -> None:
        if self._busy:
            return
        running = self._status is not None
        action = "stop" if running else "start"
        self._pending_target = not running
        self._pending_since = time.monotonic()

        def done(res: Dict[str, Any]) -> None:
            if not res.get("ok"):
                self._pending_target = None
                self._warn(res.get("msg", _("Operation failed")))
            self._tick()

        self._run([action], None, done, _("Starting…") if action == "start" else _("Stopping…"))
        self._update_buttons()

    def _autostart_clicked(self, checked: bool) -> None:
        def done(res: Dict[str, Any]) -> None:
            if not res.get("ok"):
                self._warn(res.get("msg", _("Operation failed")))
            self._sync_autostart()

        self._run(["enable" if checked else "disable"], None, done, _("Applying setting…"))

    def _save(self, _checked: bool = False, then: Optional[Callable[[], None]] = None) -> None:
        try:
            cfg = self._form_to_config()
        except (ConfigError, ValueError) as e:
            self._warn(str(e), _("Invalid setting"))
            return
        was_running = self._status is not None

        def done(res: Dict[str, Any]) -> None:
            if not res.get("ok"):
                self._warn(res.get("msg", _("Could not save")))
                return
            self._base_cfg = cfg
            if was_running:
                self._pending_target = True
                self._pending_since = time.monotonic()
                self._run(["restart"], None,
                          lambda r: self._warn(r.get("msg", ""))
                          if not r.get("ok") else None, _("Restarting the service…"))
            if then:
                then()

        self._run(["apply-config"], json.dumps(cfg), done, _("Saving settings…"))

    def _probe(self) -> None:
        domains = self._split_list(self.t_domains.text())
        if not domains:
            QMessageBox.information(self, "SplitGate", _("Enter at least one domain first."))
            return
        self.table.setRowCount(0)
        self.apply_best.setEnabled(False)
        self.probe_msg.setText(_("Trying… (this can take up to about a minute)"))

        def done(res: Dict[str, Any]) -> None:
            if not res.get("ok"):
                self.probe_msg.setText(res.get("msg", _("Test failed")))
                return
            self._last_probe = res
            self._fill_probe_table(res)

        self._run(["probe"], json.dumps(domains), done, _("Trying strategies…"))

    def _fill_probe_table(self, res: Dict[str, Any]) -> None:
        rows = res["results"]
        best = res.get("best")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            avg = f"{r['avg_ms']} ms" if r["avg_ms"] is not None else "–"
            items = [QTableWidgetItem(_(r["label"])), QTableWidgetItem(f"{r['ok']}/{r['total']}"),
                     QTableWidgetItem(avg)]
            tip = "\n".join(f"{d}: " + (f"{v['ms']} ms" if v["ok"] else v.get("err", _("error")))
                            for d, v in r["domains"].items())
            for j, it in enumerate(items):
                it.setToolTip(tip)
                if r["preset"] == best:
                    it.setBackground(QColor(46, 160, 67, 70))
                self.table.setItem(i, j, it)
        if best:
            label = _(next(r["label"] for r in rows if r["preset"] == best))
            self.probe_msg.setText(_("Recommended: {label}.{extra}", label=label, extra=""))
            self.apply_best.setEnabled(True)
        else:
            self.probe_msg.setText(verdict_text(diagnose(rows)))

    def _apply_best(self) -> None:
        if not self._last_probe or not self._last_probe.get("best"):
            return
        set_combo(self.f_preset, self._last_probe["best"])
        self._save()

    def _quick_test(self) -> None:
        host = self.q_host.text().strip()
        if not host:
            return
        self.q_btn.setEnabled(False)
        self.q_res.setText(_("trying…"))
        worker = QuickTestWorker(host, self)
        self._workers.append(worker)

        def done(res: Dict[str, Any]) -> None:
            if worker in self._workers:
                self._workers.remove(worker)
            self.q_btn.setEnabled(True)
            if res["ok"]:
                self.q_res.setText(_("✔ opened ({ms} ms, {tls})", ms=res["ms"], tls=res["tls"]))
                self.q_res.setStyleSheet(f"color: {GREEN};")
            else:
                self.q_res.setText(f"✖ {res['err'][:70]}")
                self.q_res.setStyleSheet(f"color: {RED};")

        worker.done.connect(done)
        worker.start()

    # ---- durum yenileme ----------------------------------------------------
    def _sync_autostart(self) -> None:
        val = unit_enabled()
        self.autostart.blockSignals(True)
        self.autostart.setEnabled(val is not None)
        self.autostart.setChecked(bool(val))
        self.autostart.blockSignals(False)

    def _update_buttons(self) -> None:
        for b in (self.power, self.save_btn, self.probe_btn, self.autostart):
            b.setEnabled(not self._busy)

    def _tick(self) -> None:
        self._tick_count += 1
        self._status = read_status()
        self.render_status(self._status)
        if self._tick_count % 5 == 1:
            self._sync_autostart()
        if self.tabs.currentIndex() == 3 and self._tick_count % 2 == 0:
            self._refresh_log()

    def render_status(self, st: Optional[Dict[str, Any]]) -> None:
        pending = (self._pending_target is not None
                   and time.monotonic() - self._pending_since < 10
                   and (self._pending_target == (st is None)))
        if self._pending_target is not None and not pending:
            self._pending_target = None
        if st:
            if st.get("state") == "stopping":
                color, text = AMBER, _("Stopping…")
            else:
                # Eski durum dosyalarında "check" yoktur: kontrol edilmemiş sayılır (yeşil olmaz).
                color, text = check_style(st.get("check", "idle") if st.get("state") == "running" else "idle")
            btn = _("Stop")
            mode = _("system-wide") if st["mode"] == "transparent" else _("local SOCKS5/HTTP proxy")
            preset = _(PRESETS[st["preset"]]["label"]) if st["preset"] in PRESETS else _("custom")
            net = st.get("network")
            detail = _("Mode: {mode} · Strategy: {preset}", mode=mode, preset=preset)
            if net:
                detail += " · " + net
            if st.get("check") == "failed":
                detail += "\n" + verdict_text(st.get("verdict", ""))
            self.state_detail.setText(detail)
            s = st["stats"]
            self.cards["conn"].set(f"{s['conn_active']} / {s['conn_total']}")
            self.cards["split"].set(f"{s['tls_split']} / {s['http_split']}")
            self.cards["pass"].set(str(s["passthrough"]))
            self.cards["traffic"].set(f"{fmt_bytes(s['bytes_up'])} / {fmt_bytes(s['bytes_down'])}")
            self.cards["dns"].set(str(s["dns_queries"]))
            self.cards["cache"].set(str(s["dns_cached"]))
            self.cards["uptime"].set(fmt_duration(s["uptime"]))
            self.cards["err"].set(str(s["errors"]))
            doh = st.get("doh", [])
            self.doh_label.setText(_("DoH providers: ") + ", ".join(
                f"{d['name']} {'✔' if d['ok'] else '✖'}" for d in doh) if doh else "")
            self.error_label.setText(_("Last error: {err}", err=s["last_error"]) if s.get("last_error") else "")
            if st["mode"] == "socks":
                self.state_detail.setText(self.state_detail.text() + _(" · Set it as the proxy in your browser"))
        else:
            for c in self.cards.values():
                c.set("–")
            self.doh_label.setText("")
            self.error_label.setText("")
            if pending:
                color, text, btn = AMBER, _("Starting…"), _("Stop")
            else:
                color, text, btn = GREY, _("Stopped"), _("Start")
            self.state_detail.setText("" if pending else _("Your connection flows directly"))
        if st is None and pending:
            btn = _("Please wait…")
        self.state_label.setText(text)
        self.state_label.setStyleSheet(f"color: {color};")
        self.power.setText(btn)
        self.power.setStyleSheet(f"background-color: {GREEN if not st and not pending else (RED if st else AMBER)};")
        if self.tray is not None:
            self.tray.setToolTip(f"SplitGate — {text}")
            self.tray_toggle.setText(btn if btn != _("Please wait…") else _("Start"))

    def _refresh_log(self) -> None:
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()[-300:]
            text = "".join(lines)
        except OSError:
            text = _("(The log does not exist yet; it will appear here once the service starts.)")
        if text != self.log_view.toPlainText():
            bar = self.log_view.verticalScrollBar()
            at_end = bar.value() >= bar.maximum() - 4
            self.log_view.setPlainText(text)
            if at_end:
                bar.setValue(bar.maximum())


def choose_language() -> Optional[str]:
    """First-run language picker; returns the chosen code, or None if the dialog was dismissed."""
    dlg = QDialog()
    dlg.setWindowTitle("SplitGate — Language / Dil")
    dlg.setWindowIcon(app_icon())
    lay = QVBoxLayout(dlg)
    title = QLabel("Choose your language")
    title.setObjectName("hero")
    title.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(title)
    chosen: Dict[str, str] = {}

    def pick(code: str) -> None:
        chosen["code"] = code
        dlg.accept()

    for code, name in LANGUAGES.items():
        b = QPushButton(name)
        b.setMinimumHeight(42)
        b.setMinimumWidth(260)
        b.clicked.connect(lambda _checked=False, c=code: pick(c))
        lay.addWidget(b)
    dlg.exec()
    return chosen.get("code")


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName("dpigec")
    app.setApplicationDisplayName("SplitGate")
    app.setDesktopFileName("dpigec")
    app.setStyleSheet(QSS)
    app.setWindowIcon(app_icon())
    name = single.server_name()
    guard = single.Guard(name)
    lock = guard.start()
    if lock == single.RUNNING:
        # Zaten çalışan bir kopya var: o öne gelir (gizliyse açılır); bu kopya yeni pencere açmaz.
        # Otomatik başlatmada (--minimized) pencere açtırılmaz.
        for _i in range(10):  # kilidi yeni almış kopyanın soketi henüz hazır olmayabilir
            if single.notify_running(name, 200, show="--minimized" not in argv):
                print("SplitGate is already running.", file=sys.stderr)
                return 0
            time.sleep(0.1)
        print("SplitGate is already running, but its window did not answer. "
              "If it is stuck, end the 'dpigec-gui' process and start it again.", file=sys.stderr)
        return 0
    if lock == single.FAILED:
        print("SplitGate: could not create the single-instance lock; running without it", file=sys.stderr)
    init_language()
    if normalize_language(os.environ.get("DPIGEC_LANG")) is None and saved_language() is None:
        picked = choose_language()
        if picked is not None:
            set_language(picked)
            save_language(picked)
    win = MainWindow()
    guard.on_show = win._show_window
    app.aboutToQuit.connect(guard.close)
    if win.tray is not None:
        app.setQuitOnLastWindowClosed(False)
    if "--minimized" not in argv or win.tray is None:
        win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
