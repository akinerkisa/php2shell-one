import unittest
from patchproof.policy import ubuntu_check, upstream_check, advisories


class PolicyTests(unittest.TestCase):
    def test_verified_ubuntu(self):
        res = ubuntu_check('24.04', 'php8.3-fpm', '8.3.6-0ubuntu0.24.04.13', True)
        self.assertEqual(res['status'], 'FIXED_PACKAGE')
        self.assertTrue(res['threshold_met'])

    def test_lower_ubuntu(self):
        res = ubuntu_check('24.04', 'php8.3-fpm', '8.3.6-0ubuntu0.24.04.12', True)
        self.assertEqual(res['status'], 'BELOW_FIXED_PACKAGE')

    def test_missing_provenance_does_not_mark_fixed(self):
        res = ubuntu_check('24.04', 'php8.3-fpm', '999:8.3.6-9ubuntu99', False)
        self.assertEqual(res['status'], 'UNKNOWN')
        self.assertTrue(res['threshold_met'])

    def test_different_branch_does_not_mark_fixed(self):
        res = ubuntu_check('24.04', 'php8.4-fpm', '8.4.27-0ubuntu1', True)
        self.assertEqual(res['status'], 'UNKNOWN')

    def test_older_ubuntu_esm(self):
        res = ubuntu_check('20.04', 'php7.4-fpm', '7.4.3-4ubuntu2.29+esm5', True)
        self.assertEqual(res['status'], 'FIXED_PACKAGE')
        self.assertEqual(res['support'], 'Ubuntu Pro/ESM')

    def test_upstream(self):
        self.assertEqual(upstream_check('8.3.35')['status'], 'BELOW_FIXED_VERSION')
        self.assertEqual(upstream_check('8.3.36')['status'], 'FIXED_VERSION')
        self.assertEqual(upstream_check('8.1.33')['status'], 'UNKNOWN')

    def test_all_ubuntu_releases(self):
        for release, info in advisories()['ubuntu'].items():
            name = 'php5-cli' if release == '14.04' else f"php{info['branch']}-cli"
            self.assertEqual(ubuntu_check(release, name, info['minimum'], True)['status'], 'FIXED_PACKAGE')
