import contextlib
import io
import json
import unittest
from patchproof.cli import main


class CLITests(unittest.TestCase):
    def test_upstream_version_json(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            result = main(['--upstream-version', '8.5.12', '--format', 'json'])
        data = json.loads(capture.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(data['cli']['assessment']['status'], 'FIXED_VERSION')
        self.assertEqual(data['overall'], 'UNKNOWN')

    def test_strict_fail_closed(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--upstream-version', '8.5.12', '--strict']), 3)

    def test_sarif(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            self.assertEqual(main(['--upstream-version', '8.5.11', '--format', 'sarif']), 0)
        self.assertEqual(json.loads(capture.getvalue())['version'], '2.1.0')
