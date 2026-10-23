"""Opt-in checks against a real Linux /proc and dpkg database."""
import os
from pathlib import Path
import unittest

from patchproof.probes import _file_info, package_file_integrity, package_owns_binary


@unittest.skipUnless(os.environ.get('PHP2SHELL_RUN_LINUX_INTEGRATION') == '1',
                     'set PHP2SHELL_RUN_LINUX_INTEGRATION=1 on Debian/Ubuntu')
class LinuxIntegrationTests(unittest.TestCase):
    def test_current_python_executable_inode(self):
        exe = os.readlink('/proc/self/exe')
        self.assertEqual(_file_info(Path('/proc/self'), exe), 'CURRENT_BINARY')

    def test_dpkg_owned_binary_matches_manifest(self):
        for package, path in [('dash', '/usr/bin/dash'), ('coreutils', '/usr/bin/true')]:
            if Path(path).is_file() and package_owns_binary(package, path):
                self.assertEqual(package_file_integrity(package, path), 'VERIFIED')
                return
        self.skipTest('no known dpkg-owned fixture is installed')
