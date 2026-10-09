"""Paketleme dosyalarının tutarlılık testleri."""
import json
import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dpigec import __version__, config  # noqa: E402


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class PackagingTests(unittest.TestCase):
    def test_default_config_file_matches_code_defaults(self):
        shipped = json.loads(read("data", "config.json"))
        self.assertEqual(config.normalize(shipped), config.default_config())

    def test_policy_is_valid_xml_and_points_to_ctl(self):
        tree = ET.fromstring(read("data", "org.dpigec.policy").encode("utf-8"))
        action = tree.find("action")
        self.assertEqual(action.get("id"), "org.dpigec.control")
        path = [a.text for a in action.findall("annotate")
                if a.get("key") == "org.freedesktop.policykit.exec.path"][0]
        self.assertEqual(path, "@PREFIX@/lib/dpigec/dpigecctl")

    def test_service_unit(self):
        unit = read("data", "dpigec.service")
        for needle in ("ExecStart=@PREFIX@/bin/dpigec daemon", "ExecStopPost=-@PREFIX@/bin/dpigec cleanup",
                       "CapabilityBoundingSet=CAP_NET_ADMIN", "WantedBy=multi-user.target"):
            self.assertIn(needle, unit)

    def test_scripts_are_executable_with_isolated_shebang(self):
        for name in ("dpigec", "dpigec-gui", "dpigecctl"):
            p = os.path.join(ROOT, "bin", name)
            self.assertTrue(os.access(p, os.X_OK), name)
            with open(p) as fh:
                self.assertEqual(fh.readline().strip(), "#!/usr/bin/python3 -I")
        for name in ("install.sh", "uninstall.sh"):
            self.assertTrue(os.access(os.path.join(ROOT, name), os.X_OK), name)

    def test_pkgbuild_version_matches(self):
        pkgbuild = read("packaging", "arch", "PKGBUILD")
        self.assertEqual(re.search(r"^pkgver=(.+)$", pkgbuild, re.M).group(1), __version__)

    def test_makefile_dry_run(self):
        res = subprocess.run(["make", "-n", "install", "DESTDIR=/tmp/x", "PYSITE=/usr/lib/python3.13/site-packages"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("/usr/lib/dpigec/dpigecctl", res.stdout)

    def test_shell_scripts_parse(self):
        for name in ("install.sh", "uninstall.sh"):
            res = subprocess.run(["bash", "-n", os.path.join(ROOT, name)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
