import unittest
from patchproof.versions import dpkg_compare, upstream_compare


class VersionTests(unittest.TestCase):
    def test_upstream(self):
        self.assertLess(upstream_compare('8.3.35', '8.3.36'), 0)
        self.assertEqual(upstream_compare('8.5.12', '8.5.12'), 0)
        self.assertGreater(upstream_compare('8.5.13', '8.5.12'), 0)
        with self.assertRaises(ValueError):
            upstream_compare('8.5.12rc1', '8.5.12')

    def test_dpkg(self):
        fixtures = [
            ('8.3.6-0ubuntu0.24.04.12', '8.3.6-0ubuntu0.24.04.13', -1),
            ('8.3.6-0ubuntu0.24.04.13', '8.3.6-0ubuntu0.24.04.13', 0),
            ('8.3.6-0ubuntu0.24.04.14', '8.3.6-0ubuntu0.24.04.13', 1),
            ('1:8.3.6-1', '8.3.6-0ubuntu0.24.04.13', 1),
            ('8.3.6~rc1-1', '8.3.6-1', -1),
            ('8.3.6-0ubuntu1', '8.3.6-0ubuntu1+esm1', -1),
            ('7.4.3-4ubuntu2.29+esm5', '7.4.3-4ubuntu2.29+esm4', 1),
            ('5.5.9+dfsg-1ubuntu4.29+esm18', '5.5.9+dfsg-1ubuntu4.29+esm18', 0),
            ('8.3.6-1', '8.3.6-1~candidate', 1)
        ]
        for a, b, want in fixtures:
            with self.subTest(a=a, b=b):
                self.assertEqual(dpkg_compare(a, b), want)
                self.assertEqual(dpkg_compare(b, a), -want)
