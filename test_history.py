import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import app


class HistoryTests(unittest.TestCase):
    def call(self, path, payload=None, method=None, headers=None):
        handler = object.__new__(app.Handler)
        handler.path = path
        raw = json.dumps(payload).encode() if payload is not None else b''
        handler.headers = {'Content-Length': str(len(raw)), 'Host': f'127.0.0.1:{app.PORT}',
                           'Content-Type': 'application/json', **(headers or {})}
        handler.rfile = io.BytesIO(raw)
        replies = []
        handler.reply = lambda body, status=200, **kw: replies.append((status, json.loads(body)))
        method = method or ('POST' if payload is not None else 'GET')
        getattr(handler, 'do_' + method)()
        return replies[0]

    def setUp(self):
        folder = tempfile.TemporaryDirectory(dir=app.ROOT)
        self.addCleanup(folder.cleanup)
        patcher = patch.object(app, 'DB_PATH', Path(folder.name) / 'test.db')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sample = dict(text=(app.ROOT / 'sample.log').read_text(), threshold=5, minutes=5, year=2026)

    def test_save_reopen_and_legacy_history(self):
        self.assertEqual(self.call('/history'), (200, []))
        status, result = self.call('/analyze', self.sample)
        self.assertEqual(status, 200)
        self.assertEqual(len(result['alerts']), 4)
        scan_id = result['id']
        status, reopened = self.call(f'/history/{scan_id}')
        self.assertEqual(status, 200)
        self.assertEqual(reopened['result']['source_text'], self.sample['text'])
        self.assertEqual(reopened['result']['settings']['failures'], 5)
        with app.database() as db:  # a scan saved by the old version, without summary columns
            db.execute('INSERT INTO analyses (result) VALUES (?)', (json.dumps(dict(events=[], alerts=[], skipped=0)),))
        history = self.call('/history')[1]
        self.assertEqual(len(history), 2)
        self.assertEqual((history[1]['events'], history[1]['alerts'], history[1]['high']), (12, 4, 2))
        self.assertEqual(history[0]['events'], 0)
        self.assertEqual(self.call('/history/9999')[0], 404)
        self.assertEqual(self.call('/history/invalid')[0], 400)

    def test_invalid_settings_not_saved(self):
        self.assertEqual(self.call('/analyze', dict(self.sample, threshold=0))[0], 400)
        self.assertEqual(self.call('/analyze', dict(self.sample, allowlist='bad entry'))[0], 400)
        status, body = self.call('/analyze', dict(self.sample, text='  '))
        self.assertEqual((status, body['error']), (400, 'Paste or upload some log lines first.'))
        self.assertEqual(self.call('/history')[1], [])

    def test_per_rule_settings(self):
        status, result = self.call('/analyze', dict(self.sample, failures=10, users=5, success=5, allowlist='203.0.113.50'))
        self.assertEqual(status, 200)
        self.assertEqual([a['rule'] for a in result['alerts']], ['Multiple accounts targeted'])

    def test_delete(self):
        first = self.call('/analyze', self.sample)[1]['id']
        self.call('/analyze', self.sample)
        self.assertEqual(self.call(f'/history/{first}', method='DELETE'), (200, {'deleted': 1}))
        self.assertEqual(self.call(f'/history/{first}', method='DELETE')[0], 404)
        self.assertEqual(len(self.call('/history')[1]), 1)
        self.assertEqual(self.call('/history', method='DELETE'), (200, {'deleted': 1}))
        self.assertEqual(self.call('/history')[1], [])

    def test_old_scans_are_pruned(self):
        with patch.object(app, 'MAX_SCANS', 2):
            for _ in range(3):
                self.call('/analyze', self.sample)
            self.assertEqual(len(self.call('/history')[1]), 2)

    def test_rejects_other_hosts_and_origins(self):
        self.assertEqual(self.call('/history', headers={'Host': 'evil.example:8501'})[0], 403)
        self.assertEqual(self.call('/analyze', self.sample, headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.call('/analyze', self.sample, headers={'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.call('/history')[1], [])


if __name__ == '__main__':
    unittest.main()
