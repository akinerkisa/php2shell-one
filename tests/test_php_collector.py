import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "php2shell-one.php"


@unittest.skipUnless(shutil.which("php"), "PHP CLI is not installed")
class PHPCollectorTests(unittest.TestCase):
    def test_json_inventory_is_valid_and_explicitly_non_verdict(self):
        result = subprocess.run(
            [shutil.which("php"), str(COLLECTOR), "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)

        self.assertEqual(report["tool"], "PHP2Shell One")
        self.assertEqual(report["runtime"]["sapi"], "cli")
        self.assertIn("php_version", report["runtime"])
        self.assertIn("session.upload_progress.enabled", report["configuration"])
        self.assertEqual(report["limits"]["patch_status"], "not determined")

    def test_unknown_option_fails_closed(self):
        result = subprocess.run(
            [shutil.which("php"), str(COLLECTOR), "--active-scan"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown option", result.stderr)

