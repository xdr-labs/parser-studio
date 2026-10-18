"""Deterministic stdlib smoke tests for the pinned development Multi-Pass service."""
import hashlib
import json
import pathlib
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime' / 'multipass'))

from multipass_preview_api import Handler, preview, preview_batch, allowed_origin


class EmbeddedMultiPassServiceTests(unittest.TestCase):
    def test_simple_source_and_original_bytes(self):
        source = '{"src_ip":"192.0.2.1","action":"deny"}'
        parsed = preview(source)
        self.assertEqual(parsed['sourceSha256'], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(parsed['sourceBytes'], len(source.encode()))
        self.assertFalse(parsed['nativeVerified'])
        self.assertFalse(parsed['targetVerified'])
        self.assertEqual(parsed['status'], 'SOURCE_PARSED')
        self.assertTrue(parsed['spans'])

    def test_framed_batch_event_accounting(self):
        rows = ['{"src_ip":"192.0.2.1"}', '{"src_ip":"192.0.2.2"}']
        batch = preview_batch('\n'.join(rows))
        self.assertEqual(batch['eventCount'], len(rows))
        self.assertEqual(len(batch['events']), len(rows))
        self.assertFalse(batch['nativeVerified'])
        self.assertEqual(batch['sourceSha256'], hashlib.sha256('\n'.join(rows).encode()).hexdigest())

    def test_oversize_and_untrusted_origin_rejected(self):
        with self.assertRaises(ValueError):
            preview('A' * 65537)
        self.assertTrue(allowed_origin('http://127.0.0.1:5180'))
        self.assertFalse(allowed_origin('https://attacker.example'))
        self.assertFalse(allowed_origin('http://127.0.0.1:5180.evil.example'))

    def test_loopback_health_contains_no_source(self):
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urlopen('http://127.0.0.1:%d/health' % server.server_port, timeout=5) as response:
                    body = response.read()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(body)['status'], 'ok')
                    self.assertNotIn(b'src_ip', body)
                payload = json.dumps({'raw': '{"action":"allow"}'}).encode()
                request = Request(
                    'http://127.0.0.1:%d/api/v1/multipass/preview' % server.server_port,
                    payload, {'Content-Type': 'application/json',
                              'Origin': 'http://127.0.0.1:5180'},
                    method='POST')
                with urlopen(request, timeout=5) as response:
                    preview_data = json.load(response)
                    self.assertFalse(preview_data['nativeVerified'])
                    self.assertEqual(preview_data['sourceSha256'],
                                     hashlib.sha256(b'{"action":"allow"}').hexdigest())
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
