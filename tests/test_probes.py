import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from patchproof.probes import dpkg_status, os_release, rootfs_scan, _inventory, apt_official_origin, package_file_integrity
from patchproof.report import sarif_report, text_report

DPKG = '''Package: php8.3-fpm
Status: install ok installed
Architecture: amd64
Version: 8.3.6-0ubuntu0.24.04.13
Description: example

Package: php8.3-cli
Status: deinstall ok config-files
Architecture: amd64
Version: 8.3.6-0ubuntu0.24.04.13

Package: php8.3-common
Status: install ok installed
Version: 8.3.6-0ubuntu0.24.04.13
'''


class ProbeTests(unittest.TestCase):
    def test_parse_os_and_dpkg(self):
        self.assertEqual(os_release('ID=ubuntu\nVERSION_ID="24.04"')['VERSION_ID'], '24.04')
        self.assertEqual(dpkg_status(DPKG), [{'name': 'php8.3-fpm', 'version': '8.3.6-0ubuntu0.24.04.13'}])

    def test_rootfs_no_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'etc').mkdir()
            (root/'var/lib/dpkg').mkdir(parents=True)
            (root/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            (root/'var/lib/dpkg/status').write_text(DPKG)
            result = rootfs_scan(root)
            self.assertEqual(result['packages'][0]['assessment']['status'], 'UNKNOWN')
            self.assertEqual(result['overall'], 'UNKNOWN')

    def test_current_worker_with_proof(self):
        result = _inventory('24.04', dpkg_status(DPKG), None,
                            [{'pid': 111, 'kind': 'fpm', 'branch': '8.3',
                              'binary': '/usr/sbin/php-fpm8.3', 'binary_state': 'CURRENT_BINARY',
                              'package_owner_verified': True, 'package_file_integrity': 'VERIFIED'}],
                            lambda n, v: True, 'test')
        self.assertEqual(result['overall'], 'FIXED_RUNTIME')
        self.assertEqual(len(sarif_report(result)['runs'][0]['results']), 2)
        self.assertIn('FIXED_RUNTIME', text_report(result))

    def test_unowned_worker_not_marked_fixed(self):
        result = _inventory('24.04', dpkg_status(DPKG), None,
                            [{'pid': 333, 'kind': 'fpm', 'branch': '8.3',
                              'binary': '/opt/unowned/php-fpm8.3', 'binary_state': 'CURRENT_BINARY'}],
                            lambda n, v: True, 'test')
        self.assertEqual(result['overall'], 'UNKNOWN')

    def test_old_worker_restart_needed(self):
        result = _inventory('24.04', dpkg_status(DPKG), None,
                            [{'pid': 222, 'kind': 'fpm', 'branch': '8.3',
                              'binary': '/usr/sbin/php-fpm8.3 (deleted)', 'binary_state': 'STALE_BINARY'}],
                            lambda n, v: True, 'test')
        self.assertEqual(result['overall'], 'RESTART_REQUIRED')

    def test_integrity_mismatch_fails_closed(self):
        result = _inventory('24.04', dpkg_status(DPKG), None,
                            [{'pid': 444, 'kind': 'fpm', 'branch': '8.3',
                              'binary': '/usr/sbin/php-fpm8.3', 'binary_state': 'CURRENT_BINARY',
                              'package_owner_verified': True, 'package_file_integrity': 'MISMATCH'}],
                            lambda n, v: True, 'test')
        self.assertEqual(result['overall'], 'INTEGRITY_MISMATCH')

    def test_package_integrity_missing_manifest_fails_closed(self):
        with patch('patchproof.probes._run', return_value='php8.3-fpm'), \
             patch('patchproof.probes._file_text', return_value=''):
            self.assertEqual(package_file_integrity('php8.3-fpm', '/usr/sbin/php-fpm8.3'), 'UNAVAILABLE')

    def test_policy_provenance(self):
        mock = '''php8.3-fpm:
  Installed: 8.3.6-0ubuntu0.24.04.13
  Version table:
 *** 8.3.6-0ubuntu0.24.04.13 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
        100 /var/lib/dpkg/status
     8.3.6-0ubuntu0.24.04.12 500
        500 https://ppa.launchpadcontent.net/random/ubuntu noble/main amd64 Packages
'''
        with patch('patchproof.probes._run', return_value=mock):
            self.assertTrue(apt_official_origin('php8.3-fpm', '8.3.6-0ubuntu0.24.04.13'))
            self.assertFalse(apt_official_origin('php8.3-fpm', '8.3.6-0ubuntu0.24.04.12'))
