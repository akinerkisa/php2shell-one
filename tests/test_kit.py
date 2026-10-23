import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from php2shellkit.common import envelope, format_report
from php2shellkit.cli import main
from php2shellkit.configcheck import inspect_configs
from php2shellkit.hunt import scan_logs, read_iocs, _access_fields, _time
from php2shellkit.repoaudit import evaluate_image, audit_repo
from php2shellkit.webcheck import web_head


class KitTests(unittest.TestCase):
    def test_one_catalog_marks_proof_not_implemented(self):
        from php2shellkit.capabilities import one_status
        report = one_status()
        self.assertTrue(any('differential-proof: not-implemented' in f['message'] for f in report['findings']))
        self.assertEqual(main(['capabilities']), 0)

    def test_capabilities_command_selects_readiness_view(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'capabilities.json'
            self.assertEqual(main(['capabilities', '--format', 'json', '--output', str(dest)]), 0)
            report = json.loads(dest.read_text(encoding='utf-8'))
            self.assertTrue(any('differential-proof: not-implemented' in finding['message']
                                for finding in report['findings']))

    def test_one_quick_report_autodiscovers_bounded_inputs(self):
        from php2shellkit.one import quick_report
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'Dockerfile').write_text('FROM php:8.3.35-fpm\n')
            (root/'php.ini').write_text('session.upload_progress.enabled=On\n')
            (root/'error.log').write_text('PHP out of memory\n')
            report = quick_report(root, local=False)
            self.assertEqual(report['command'], 'one')
            self.assertEqual(report['summary']['total'], 3)
            self.assertEqual(report['quick_inputs']['local_runtime'], False)
            self.assertTrue(any('does not mean' in item for item in report['limitations']))

    def test_one_cli_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'Dockerfile').write_text('FROM php:8.3.36-fpm\n')
            dest = root/'one.json'
            self.assertEqual(main(['one', td, '--no-local', '--format', 'json', '--output', str(dest)]), 0)
            self.assertEqual(json.loads(dest.read_text())['tool'], 'php2shell-one')

    def test_upstream_status(self):
        self.assertEqual(main(['status']), 0)

    def test_verify_strict_unknown(self):
        self.assertEqual(main(['verify','--version','8.3.36','--strict']), 3)

    def test_repo_unsafe_pin(self):
        self.assertEqual(evaluate_image('php:8.3.35-fpm')['rule_id'], 'PHP_TAG_BELOW_FIXED')

    def test_repo_fixed_tag_not_attested(self):
        self.assertEqual(evaluate_image('php:8.3.36-cli')['rule_id'], 'PHP_TAG_FIXED_CLAIM')

    def test_repo_docker_prefix(self):
        self.assertEqual(evaluate_image('docker.io/library/php:8.4.26-fpm')['severity'], 'high')

    def test_repo_non_php(self):
        self.assertIsNone(evaluate_image('nginx:latest'))

    def test_repo_moving_tag(self):
        self.assertEqual(evaluate_image('php:8.3-fpm')['rule_id'], 'MOVING_PHP_TAG')

    def test_repo_digest_not_attested(self):
        self.assertEqual(evaluate_image('php@sha256:' + 'a'*64)['rule_id'], 'DIGEST_UNVERIFIED')

    def test_repo_dynamic_tag(self):
        self.assertEqual(evaluate_image('${PHP_IMAGE}')['rule_id'], 'DYNAMIC_IMAGE')

    def test_repo_scan(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p/'Dockerfile').write_text('FROM php:8.3.35-fpm\nRUN echo safe\n')
            (p/'compose.yml').write_text('services:\n  api:\n    image: php:8.3.36-cli\n')
            r = audit_repo(p)
            self.assertEqual(len(r['findings']), 2)
            self.assertEqual(r['summary']['high'], 1)

    def test_repo_skips_vendor_folder(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'vendor'
            p.mkdir()
            (p/'Dockerfile').write_text('FROM php:8.3.35\n')
            self.assertEqual(audit_repo(Path(td))['summary']['total'], 0)

    def test_repo_bad_path(self):
        with self.assertRaises(ValueError):
            audit_repo(Path('/unlikely/nonexistent/repo'))

    def test_config_heuristics(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'php.ini'
            p.write_text(';comment\nsession.upload_progress.enabled=On\nexpose_php=On\n')
            r = inspect_configs([p])
            self.assertEqual(r['summary']['low'], 1)
            self.assertEqual(r['summary']['info'], 1)

    def test_config_admin_flags(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'pool.conf'
            p.write_text('php_admin_flag[session.upload_progress.enabled] = off\n')
            r = inspect_configs([p])
            self.assertEqual(r['findings'][0]['severity'], 'info')

    def test_config_missing(self):
        with self.assertRaises(ValueError):
            inspect_configs([Path('/unlikely/foo/php.ini')])

    def test_access_parser(self):
        self.assertEqual(_access_fields('192.0.2.1 - - [21/Oct/2026:12:00:00 +0000] "POST /upload.php HTTP/1.1" 500 1')['status'],'500')
        self.assertEqual(_access_fields('{"remote_addr":"192.0.2.1","status":500,"method":"POST"}')['method'],'POST')
        self.assertIsNone(_access_fields('unparseable'))

    def test_time(self):
        self.assertEqual(_time('2026-10-21T12:00:00Z').year, 2026)
        self.assertIsNone(_time('bad'))

    def test_ioc_validation(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'ioc.json'
            p.write_text('{"ips":["192.0.2.1"],"sha256":["' + 'a'*64 + '"]}')
            self.assertIn('192.0.2.1', read_iocs(p)['ips'])
            p.write_text('{"ips":["999.999.0.1"]}')
            with self.assertRaises(ValueError):
                read_iocs(p)

    def test_hunt_no_files(self):
        with self.assertRaises(ValueError):
            scan_logs()

    def test_hunt_redaction_and_burst(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'access.log'
            ln = '192.0.2.20 - - [21/Oct/2026:12:02:14 +0000] "POST /upload.php?secret=NEVER_EXPOSE HTTP/1.1" 500 300\n'
            p.write_text(ln*6)
            report = scan_logs(access=[p])
            self.assertEqual(report['findings'][0]['rule_id'], 'POST_5XX_BURST')
            serial = json.dumps(report)
            self.assertNotIn('192.0.2.20',serial)
            self.assertNotIn('NEVER_EXPOSE',serial)
            self.assertIn('client-',serial)

    def test_hunt_show_ips_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'access.log'
            p.write_text(('192.0.2.20 - - [21/Oct/2026:12:02:14 +0000] "POST /upload.php HTTP/1.1" 500 1\n')*5)
            self.assertIn('192.0.2.20', json.dumps(scan_logs(access=[p],show_ips=True)))

    def test_hunt_gz(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'error.log.gz'
            with gzip.open(p,'wt') as f:
                f.write('PHP Fatal error: Allowed memory size of 1 bytes exhausted\n')
            self.assertEqual(scan_logs(error=[p])['findings'][0]['rule_id'],'PHP_OOM')

    def test_hunt_jsonl_child(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'events.jsonl'
            p.write_text('{"process":{"name":"curl","parent":{"name":"php-fpm8.3"}}}\n')
            self.assertEqual(scan_logs(events=[p])['findings'][0]['rule_id'],'PHP_CHILD_PROCESS')

    def test_hunt_event_hash(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'events.jsonl'
            p.write_text(json.dumps({'process':{'hash':{'sha256':'a'*64}}})+'\n')
            i = Path(td)/'ioc.json'; i.write_text(json.dumps({'sha256':['a'*64]}))
            self.assertEqual(scan_logs(events=[p],ioc_file=i)['findings'][0]['rule_id'],'IOC_SHA256')

    def test_hunt_since(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'access.log'
            p.write_text('192.0.2.1 - - [21/Oct/2026:12:00:00 +0000] "POST /x?PHP_SESSION_UPLOAD_PROGRESS=test HTTP/1.1" 500 1\n')
            self.assertEqual(scan_logs(access=[p], since='2026-10-22T00:00:00Z')['summary']['total'], 0)
            with self.assertRaises(ValueError):
                scan_logs(access=[p], since='not a date')

    def test_hunt_max_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'error.log'
            p.write_text(('PHP out of memory\n')*3)
            r = scan_logs(error=[p], max_lines=2)
            self.assertEqual(r['summary']['total'], 2)
            self.assertIn('Line limits', r['limitations'][-1])

    def test_hunt_rejects_oversized_line(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'error.log'
            p.write_text('x' * 1_000_001)
            with self.assertRaises(ValueError):
                scan_logs(error=[p])

    def test_repo_max_files_counts_all_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'a.txt').write_text('x')
            (root/'b.txt').write_text('x')
            (root/'Dockerfile').write_text('FROM php:8.3.35-fpm')
            report = audit_repo(root, max_files=1)
            self.assertTrue(any('limit reached' in n.lower() for n in report['limitations']))

    def test_html_escaped(self):
        report = envelope('example', [{'severity':'low','rule_id':'X','source':'<script>alert(1)</script>','line':1,'message':'<b>x</b>'}])
        out = format_report(report,'html')
        self.assertIn('&lt;script&gt;', out)
        self.assertNotIn('<script>', out)

    def test_json_format(self):
        report = envelope('example',[])
        self.assertEqual(json.loads(format_report(report,'json'))['command'],'example')

    def test_csv_format(self):
        report = envelope('example',[])
        self.assertIn('severity,rule_id,source,line,message,evidence',format_report(report,'csv'))

    def test_sarif_format(self):
        r = envelope('x',[{'severity':'high','rule_id':'RULE','source':'foo','line':1,'message':'message'}])
        self.assertEqual(json.loads(format_report(r,'sarif'))['version'],'2.1.0')

    def test_rules_list_and_show(self):
        self.assertEqual(main(['rules','list']),0)
        self.assertEqual(main(['rules','show','modsecurity/request-limits.conf']),0)

    def test_webcheck_requires_auth(self):
        with self.assertRaises(ValueError):
            web_head('https://example.org/', False)

    def test_webcheck_bad_urls(self):
        for url in ['file:///etc/passwd', 'http://name:pass@example.org/', 'not-a-url']:
            with self.assertRaises(ValueError):
                web_head(url, True)

    def test_webcheck_mock_head(self):
        class Resp:
            status = 200
            headers = {'X-Powered-By':'PHP/8.3.36'}
            def __enter__(self): return self
            def __exit__(self,*args): pass
        class Opener:
            def open(self, request, timeout):
                self_type = request.get_method()
                if self_type != 'HEAD': raise AssertionError('non-HEAD sent')
                return Resp()
        with patch('php2shellkit.webcheck.build_opener', return_value=Opener()):
            result = web_head('https://example.org/', True)
        self.assertEqual(result['findings'][0]['rule_id'],'DISCLOSED_PHP_VERSION')
        self.assertTrue(any('NEVER' in n for n in result['limitations']))

    def test_cli_hunt_json(self):
        with tempfile.TemporaryDirectory() as td:
            access=Path(td)/'access.log'; access.write_text('')
            dest=Path(td)/'out.json'
            self.assertEqual(main(['hunt','--access-log',str(access),'--format','json','--output',str(dest)]),0)
            self.assertEqual(json.loads(dest.read_text())['command'],'hunt')

    def test_cli_repo_fail_on_high(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'Dockerfile').write_text('FROM php:8.3.35-fpm')
            self.assertEqual(main(['repo-audit',td,'--fail-on','high']),2)

    def test_cli_config_html(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'php.ini'; p.write_text('memory_limit=128M\n')
            out=Path(td)/'report.html'
            self.assertEqual(main(['config-audit',str(p),'--format','html','--output',str(out)]),0)
            self.assertIn('<!doctype html>',out.read_text())


class CompositeTests(unittest.TestCase):
    def test_combined_audit(self):
        from php2shellkit.assessment import assess
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'Dockerfile').write_text('FROM php:8.3.35-fpm\n')
            ini=root/'php.ini'; ini.write_text('session.upload_progress.enabled=On\n')
            log=root/'error.log'; log.write_text('PHP out of memory\n')
            report=assess(repo=root,configs=[ini],errors=[log])
            self.assertEqual(report['summary']['total'],3)
            self.assertEqual(report['summary']['high'],1)
    def test_assess_empty_rejected(self):
        from php2shellkit.assessment import assess
        with self.assertRaises(ValueError):
            assess()
    def test_assess_cli_html(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'Dockerfile').write_text('FROM php:8.4.27-fpm')
            dest=root/'out.html'
            self.assertEqual(main(['assess','--repo',td,'--format','html','--output',str(dest)]),0)
            self.assertIn('PHP2Shell',dest.read_text())


if __name__ == '__main__':
    unittest.main()
