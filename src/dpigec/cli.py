# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Komut satırı arayüzü: dpigec <komut>."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys

from . import __version__, firewall
from .i18n import (LANGUAGES, _, init as init_language, language, normalize_language,
                   save_language, set_language)
from .config import (ConfigError, STATUS_FILE, SYSTEM_CONFIG, default_config,
                     default_config_path, load_config)
from .engine import run_engine
from .status import read_status

from .ctlclient import CTL


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _privileged(args, stdin_text=None) -> int:
    """root gerektiren işi dpigecctl üzerinden çalıştırır (gerekirse pkexec ile)."""
    ctl = CTL if os.path.exists(CTL) else None
    if ctl is None:
        cmd = [sys.executable, "-I", "-m", "dpigec.ctl", "--lang", language(), *args]
    else:
        cmd = [ctl, "--lang", language(), *args]
    if os.geteuid() != 0:
        pk = shutil.which("pkexec")
        if not pk:
            print(_("error: root privileges required (pkexec not found); run with sudo"), file=sys.stderr)
            return 1
        cmd = [pk, *cmd]
    res = subprocess.run(cmd, input=stdin_text, text=True, capture_output=True)
    line = (res.stdout.strip().splitlines() or ["{}"])[-1]
    try:
        data = json.loads(line)
    except ValueError:
        print(res.stderr.strip() or _("unexpected output"), file=sys.stderr)
        return 1
    print(data.get("msg", _("done") if data.get("ok") else _("error")))
    return 0 if data.get("ok") else 1


def cmd_status(_args) -> int:
    st = read_status()
    if not st:
        print(_("state: stopped"))
        return 3
    s = st["stats"]
    rows = [
        (_("state"), _("{state} (mode: {mode}, strategy: {preset})", state=st["state"], mode=st["mode"],
                       preset=st["preset"])),
        (_("uptime"), _("{n} s", n=s["uptime"])),
        (_("connections"), _("{active} active / {total} total", active=s["conn_active"], total=s["conn_total"])),
        (_("split"), _("TLS {tls}, HTTP {http}, direct {direct}", tls=s["tls_split"], http=s["http_split"],
                       direct=s["passthrough"])),
        (_("traffic"), f"↑ {_fmt_bytes(s['bytes_up'])}  ↓ {_fmt_bytes(s['bytes_down'])}"),
        ("DNS", _("{q} queries, {c} from cache, {f} errors", q=s["dns_queries"], c=s["dns_cached"],
                  f=s["dns_failed"])),
    ]
    if st.get("network"):
        rows.insert(1, (_("network"), st["network"]))
    check = st.get("check")
    if check:
        rows.insert(2, (_("check"), _check_text(st)))
    if s.get("last_error"):
        rows.append((_("last error"), s["last_error"]))
    width = max(len(label) for label, _v in rows) + 1
    for label, value in rows:
        print(f"{label:<{width}}: {value}")
    return 0


def _check_text(st) -> str:
    from .config import PRESETS
    from .probe import verdict_text
    check = st.get("check")
    method = st.get("active_preset", "")
    label = _(PRESETS[method]["label"]) if method in PRESETS else method
    if check == "working":
        return _("WORKING: {method} opens {detail} test sites", method=label, detail=st.get("check_detail", ""))
    if check == "not_blocked":
        return _("connected; the test sites are not blocked on this network")
    if check == "failed":
        return _("NOT WORKING on this network: {why}", why=verdict_text(st.get("verdict", "")))
    if check == "checking":
        return _("checking…")
    return _("not checked yet")


def cmd_report(args) -> int:
    from . import report
    from .config import LOG_FILE
    cfg = load_config(args.config)
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    text = report.build(cfg, read_status(), args.note or "", lines)
    print(text)
    if args.mail:
        url = report.mailto(text, _("SplitGate {version} report", version=__version__))
        opener = shutil.which("xdg-open")
        if not opener:
            print(_("xdg-open not found; copy the report above and send it to {to}", to=report.TO), file=sys.stderr)
            return 1
        subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0


def cmd_daemon(args) -> int:
    cfg = load_config(args.config or SYSTEM_CONFIG)
    return run_engine(cfg, console=True)


def cmd_run(args) -> int:
    """Ön planda çalıştır. Root değilse otomatik olarak yerel SOCKS5 moduna geçer."""
    cfg = load_config(args.config)
    if args.mode:
        cfg["mode"] = args.mode
    elif os.geteuid() != 0 and cfg["mode"] == "transparent":
        print(_("not running as root, using local SOCKS5/HTTP proxy mode (127.0.0.1:{port})",
                port=cfg["socks_port"]), file=sys.stderr)
        cfg["mode"] = "socks"
    if os.geteuid() == 0:
        status_path = STATUS_FILE
    else:
        status_path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "dpigec-status.json")
    return run_engine(cfg, console=True, logfile=None, status_path=status_path)


def cmd_probe(args) -> int:
    from .probe import NOT_BLOCKED, best_preset, diagnose, run_probe, verdict_text
    cfg = load_config(args.config)
    domains = args.domains or None

    def progress(_key, label):
        print(_("  trying: {label} ...", label=_(label)), file=sys.stderr)

    results = asyncio.run(run_probe(cfg, domains, progress))
    print(f"{_('Strategy'):<34}{_('Opened'):>8}{_('Avg. time'):>12}")
    for r in results:
        avg = f"{r['avg_ms']} ms" if r["avg_ms"] is not None else "-"
        print(f"{_(r['label']):<34}{r['ok']:>3}/{r['total']:<4}{avg:>12}")
    best = best_preset(results)
    verdict = diagnose(results)
    print("\n" + (_("recommended: {best}", best=best) if best else verdict_text(verdict)))
    return 0 if best or verdict == NOT_BLOCKED else 2


def cmd_config(args) -> int:
    if args.print_default:
        print(json.dumps(default_config(), indent=2, ensure_ascii=False))
        return 0
    path = args.config or default_config_path()
    print(path)
    cfg = load_config(path)
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
    return 0


def cmd_cleanup(_args) -> int:
    if os.geteuid() == 0:  # servis ExecStopPost'u burada root olarak çalışır
        print(_("rules removed") if firewall.remove() else _("no rules to remove"))
        return 0
    return _privileged(["cleanup"])


def cmd_lang(args) -> int:
    if args.code is None:
        print(f"{language()}  ({LANGUAGES[language()]})")
        print(_("available: {langs}", langs=", ".join(f"{c} ({n})" for c, n in LANGUAGES.items())))
        return 0
    code = normalize_language(args.code)
    if code is None:
        print(_("unknown language: {code}", code=args.code), file=sys.stderr)
        return 2
    set_language(code)
    if not save_language(code):
        print(_("could not save the language choice"), file=sys.stderr)
        return 1
    print(_("language set: {name}", name=LANGUAGES[code]))
    return 0


def cmd_rules(args) -> int:
    cfg = load_config(args.config)
    print(firewall.render_ruleset(cfg))
    return 0


def main(argv=None) -> int:
    init_language()
    ap = argparse.ArgumentParser(prog="dpigec", description=_("SplitGate - DPI bypass tool (Linux)"))
    ap.add_argument("--version", action="version", version=f"dpigec {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, helptext in (("start", _("start the service")), ("stop", _("stop the service")),
                           ("restart", _("restart the service")),
                           ("enable", _("start automatically at boot")), ("disable", _("disable automatic start"))):
        p = sub.add_parser(name, help=helptext)
        p.set_defaults(fn=(lambda a, n=name: _privileged([n])))

    p = sub.add_parser("status", help=_("show the status"))
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("check", help=_("try the current method on the test sites again"))
    p.set_defaults(fn=lambda a: _privileged(["recheck"]))
    p = sub.add_parser("report", help=_("make a problem report (no visited sites in it)"))
    p.add_argument("--config")
    p.add_argument("--note", help=_("what is the problem (written at the top of the report)"))
    p.add_argument("--mail", action="store_true", help=_("open your e-mail app with the report"))
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("daemon", help=_("(service) run the engine in the foreground"))
    p.add_argument("--config")
    p.set_defaults(fn=cmd_daemon)
    p = sub.add_parser("run", help=_("run in the foreground (SOCKS5 mode when not root)"))
    p.add_argument("--config")
    p.add_argument("--mode", choices=("transparent", "socks"))
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("probe", help=_("find the best strategy automatically"))
    p.add_argument("--config")
    p.add_argument("domains", nargs="*")
    p.set_defaults(fn=cmd_probe)
    p = sub.add_parser("config", help=_("show the configuration"))
    p.add_argument("--config")
    p.add_argument("--print-default", action="store_true")
    p.set_defaults(fn=cmd_config)
    p = sub.add_parser("cleanup", help=_("remove the nftables rules"))
    p.set_defaults(fn=cmd_cleanup)
    p = sub.add_parser("lang", help=_("show or set the interface language"))
    p.add_argument("code", nargs="?")
    p.set_defaults(fn=cmd_lang)
    p = sub.add_parser("rules", help=_("print the nftables rules that would be applied"))
    p.add_argument("--config")
    p.set_defaults(fn=cmd_rules)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as e:
        print(_("configuration error: {e}", e=e), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
