"""Translation catalog consistency and language selection safety."""
import ast
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dpigec import i18n, config  # noqa: E402
from dpigec.i18n_tr import CATALOG  # noqa: E402

PLACEHOLDER = re.compile(r"{(\w+)(?:[^}]*)}")


def source_messages():
    found = set()
    base = os.path.join(ROOT, "src", "dpigec")
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            if not name.endswith(".py") or name.startswith("i18n"):
                continue
            tree = ast.parse(open(os.path.join(dirpath, name), encoding="utf-8").read())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_"
                        and node.args and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)):
                    found.add(node.args[0].value)
    return found


class CatalogTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en")

    def test_every_source_message_has_a_turkish_translation(self):
        missing = sorted(m for m in source_messages() if m not in CATALOG)
        self.assertEqual(missing, [])

    def test_preset_and_probe_labels_are_translated(self):
        for p in config.PRESETS.values():
            self.assertIn(p["label"], CATALOG)
        self.assertIn("No splitting (baseline)", CATALOG)

    def test_placeholders_match_between_languages(self):
        for en, tr in CATALOG.items():
            self.assertEqual(sorted(PLACEHOLDER.findall(en)), sorted(PLACEHOLDER.findall(tr)), en)

    def test_catalog_has_no_unused_entries(self):
        used = source_messages() | {p["label"] for p in config.PRESETS.values()}
        used |= {"No splitting (baseline)", "Custom provider"}
        gui_text = open(os.path.join(ROOT, "src", "dpigec", "gui", "app.py"), encoding="utf-8").read()
        unused = [k for k in CATALOG if k not in used and ('"%s"' % k) not in gui_text
                  and k not in gui_text and k.split("{")[0] not in gui_text]
        self.assertEqual(unused, [])

    def test_placeholder_named_msg_does_not_crash(self):
        from dpigec.i18n import _
        self.assertEqual(_("certificate: {msg}", msg="x").split(": ")[-1], "x")
        self.assertEqual(_("DNS: {msg}", msg="y").split(": ")[-1], "y")

    def test_translation_and_fallback(self):
        i18n.set_language("tr")
        self.assertEqual(i18n._("Start"), "Başlat")
        self.assertEqual(i18n._("no such message {x}", x=1), "no such message 1")
        i18n.set_language("en")
        self.assertEqual(i18n._("Start"), "Start")

    def test_unknown_language_codes_fall_back_to_english(self):
        for bad in ("xx", "../etc/passwd", "", None, 5, "tr\n"):
            self.assertEqual(i18n.set_language(bad), "en")
        self.assertIsNone(i18n.normalize_language("../x"))

    def test_saved_language_roundtrip_and_tolerance(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("XDG_CONFIG_HOME")
            os.environ["XDG_CONFIG_HOME"] = d
            try:
                self.assertIsNone(i18n.saved_language())
                self.assertTrue(i18n.save_language("tr"))
                self.assertEqual(i18n.saved_language(), "tr")
                self.assertFalse(i18n.save_language("klingon"))
                with open(i18n.pref_path(), "w", encoding="utf-8") as fh:
                    fh.write("not json")
                self.assertIsNone(i18n.saved_language())
                with open(i18n.pref_path(), "w", encoding="utf-8") as fh:
                    json.dump({"lang": "../../x"}, fh)
                self.assertIsNone(i18n.saved_language())
            finally:
                if old is None:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                else:
                    os.environ["XDG_CONFIG_HOME"] = old

    def test_default_without_saved_choice_is_english(self):
        with tempfile.TemporaryDirectory() as d:
            saved = {k: os.environ.get(k) for k in ("XDG_CONFIG_HOME", "DPIGEC_LANG")}
            os.environ["XDG_CONFIG_HOME"] = d
            os.environ.pop("DPIGEC_LANG", None)
            try:
                self.assertEqual(i18n.init(), "en")
                os.environ["DPIGEC_LANG"] = "tr"
                self.assertEqual(i18n.init(), "tr")
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_privileged_helper_accepts_only_allowlisted_language(self):
        from dpigec import ctl
        for code, expect in (("tr", "bilinmeyen komut: nope"), ("en", "unknown command: nope"),
                             ("../../etc/passwd", "unknown command: nope"), ("xx", "unknown command: nope")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ctl.main(["--lang", code, "nope"])
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(buf.getvalue())["msg"], expect, code)

    def test_config_errors_are_localized(self):
        i18n.set_language("tr")
        with self.assertRaises(config.ConfigError) as cm:
            config.normalize({"socks_port": 5})
        self.assertIn("arasında tam sayı olmalı", str(cm.exception))
        i18n.set_language("en")
        with self.assertRaises(config.ConfigError) as cm:
            config.normalize({"socks_port": 5})
        self.assertIn("must be an integer between", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
