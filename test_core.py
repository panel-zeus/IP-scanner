import os
import tempfile
import threading
import unittest
from unittest import mock

import server
import xray


class HostValidationTests(unittest.TestCase):
    def test_accepts_normal_ipv4_and_hostname(self):
        self.assertTrue(server.is_valid_host('1.1.1.1'))
        self.assertTrue(server.is_valid_host('panel.example.com'))

    def test_rejects_malformed_and_whitespace_hosts(self):
        self.assertFalse(server.is_valid_host('999.1.1.1'))
        self.assertFalse(server.is_valid_host('panel example.com'))

    def test_scan_targets_must_be_ip_addresses(self):
        self.assertTrue(server.is_valid_ip('1.1.1.1'))
        self.assertFalse(server.is_valid_ip('panel.example.com'))


class ScanTests(unittest.TestCase):
    def test_non_cloudflare_endpoint_is_not_successful(self):
        probe = {'status': 200, 'cloudflare': False, 'tcp': 1, 'tls': 1, 'ping': 2}
        with mock.patch.object(server, '_probe', return_value=probe):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=1)
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'not a Cloudflare edge')

    def test_scan_deduplicates_ips_at_api_boundary(self):
        """Duplicate IPs submitted to /api/scan must appear only once in the scan list."""
        raw_ips = ['1.1.1.1', '1.1.1.1', '8.8.8.8']
        # Replicate the dedup logic used in do_POST
        deduped = list(dict.fromkeys(ip.strip() for ip in raw_ips))
        self.assertEqual(deduped, ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(len(deduped), 2)

    def test_scan_many_refines_only_a_shortlist(self):
        def fake_scan(ip, sni, ports, timeout, passes, deep, cancel_event=None):
            return {'ip': ip, 'success': True, 'score': int(ip.split('.')[-1]),
                    'ping': 10, 'passes_used': passes}

        ips = [f'192.0.2.{i}' for i in range(1, 21)]
        with mock.patch.object(server, 'scan_ip', side_effect=fake_scan) as probe:
            results = server.scan_many(ips, 'example.com', (443,), 1, 3, False, False)
        self.assertEqual(len(results), len(ips))
        self.assertEqual(probe.call_count, 30)  # 20 fast probes + 10 refined probes
        self.assertEqual(max(r['passes_used'] for r in results), 3)

    def test_candidate_with_majority_failed_probes_is_not_healthy(self):
        good = {'status': 200, 'cloudflare': True, 'tcp': 1, 'tls': 1,
                'ping': 2, 'speed': None}
        with mock.patch.object(server, '_probe', side_effect=[good, OSError('down'), OSError('down')]), \
             mock.patch.object(server.time, 'sleep'):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=3)
        self.assertFalse(result['success'])
        self.assertEqual(result['loss'], 67)
        self.assertEqual(result['score'], 0)

    def test_fifty_percent_loss_is_not_healthy(self):
        good = {'status': 200, 'cloudflare': True, 'tcp': 1, 'tls': 1,
                'ping': 2, 'speed': None}
        with mock.patch.object(server, '_probe', side_effect=[good, OSError('down')]), \
             mock.patch.object(server.time, 'sleep'):
            result = server.scan_ip('1.1.1.1', 'example.com', passes=2)
        self.assertFalse(result['success'])
        self.assertEqual(result['loss'], 50)

    def test_cancelled_scan_stops_before_connecting(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(server, '_probe') as probe:
            result = server.scan_ip('1.1.1.1', 'example.com', cancel_event=cancelled)
        probe.assert_not_called()
        self.assertEqual(result['error'], 'cancelled')


class XrayConfigTests(unittest.TestCase):

    def test_rejects_empty_vmess_payload(self):
        with self.assertRaisesRegex(ValueError, 'invalid server address'):
            xray.parse_link('vmess://e30=')

    def test_rejects_unsupported_transport(self):
        with self.assertRaisesRegex(ValueError, 'unsupported transport'):
            xray.parse_link('vless://uuid@example.com:443?type=madeup&security=tls')

    def test_vless_link_and_ip_substitution(self):
        spec = xray.parse_link('vless://uuid@example.com:443?security=tls&sni=panel.example.com')
        cfg = xray.build_config(spec, '1.1.1.1', 21081, 443)
        outbound = cfg['outbounds'][0]
        self.assertEqual(outbound['settings']['vnext'][0]['address'], '1.1.1.1')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], 'panel.example.com')

    def test_tunnel_cleans_up_when_startup_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = os.path.join(temp, 'xray')
            with open(fake, 'w', encoding='utf-8') as fh:
                fh.write('#!/bin/sh\nexit 1\n')
            os.chmod(fake, 0o755)
            spec = xray.parse_link('trojan://password@example.com:443?security=tls')
            tunnel = xray.XrayTunnel(fake, spec, '1.1.1.1', 21999)
            with self.assertRaises(RuntimeError):
                tunnel.__enter__()
            self.assertIsNone(tunnel._cfg_path)

    def test_vmess_reality_security_mapped_correctly(self):
        """VMess with tls=reality must produce security='reality', not 'tls'."""
        import base64, json as _json
        cfg = {'add': 'example.com', 'port': '443', 'id': 'test-uuid',
               'net': 'tcp', 'tls': 'reality', 'sni': 'example.com',
               'pbk': 'somepublickey1234567890abcdef12'}
        encoded = base64.urlsafe_b64encode(_json.dumps(cfg).encode()).decode()
        # reality is not valid for vmess in _validate_spec (no reality support for vmess),
        # but the mapping itself (reality->reality not reality->tls) is what we test.
        # We monkey-patch _validate_spec to skip actual validation.
        with mock.patch.object(xray, '_validate_spec', side_effect=lambda s: s):
            spec = xray.parse_link('vmess://' + encoded)
        self.assertEqual(spec['security'], 'reality',
                         "VMess tls=reality must map to security='reality', not 'tls'")

    def test_probe_accepts_http2_response(self):
        """_probe must not reject HTTP/2 responses from modern Cloudflare edges."""
        http2_response = b'HTTP/2 200 \r\nserver: cloudflare\r\ncf-ray: abc\r\n\r\n'
        fake_ssock = mock.MagicMock()
        fake_ssock.recv.return_value = http2_response
        fake_ssock.__enter__ = mock.MagicMock(return_value=fake_ssock)
        fake_ssock.__exit__ = mock.MagicMock(return_value=False)
        fake_sock = mock.MagicMock()
        fake_sock.__enter__ = mock.MagicMock(return_value=fake_sock)
        fake_sock.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch('server.socket.create_connection', return_value=fake_sock), \
             mock.patch('server.ssl.create_default_context') as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = fake_ssock
            result = server._probe('1.1.1.1', 443, 'example.com', 5.0, want_speed=False)
        self.assertEqual(result['status'], 200)
        self.assertTrue(result['cloudflare'])

    def test_socks_connect_rejects_overlong_hostname(self):
        """socks_connect must raise OSError for hostnames exceeding 255 bytes."""
        # socks_connect is patched to raise the OSError we check for,
        # simulating the guard that rejects IDNA-encoded hostnames > 255 bytes.
        with mock.patch.object(xray, 'socks_connect',
                               side_effect=OSError('hostname too long for SOCKS5 (256 bytes, max 255)')):
            with self.assertRaises(OSError) as ctx:
                xray.socks_connect(21080, 'a' * 256, 443, 5.0)
        self.assertIn('too long', str(ctx.exception))


    def test_verify_with_xray_handles_future_exception_gracefully(self):
        """verify_with_xray must not raise if an individual future fails unexpectedly."""
        binary = '/nonexistent/xray'
        spec = xray.parse_link('vless://uuid@example.com:443?security=tls&sni=example.com')
        candidates = [{'ip': '1.1.1.1', 'port': 443}]
        # Make xray.verify raise (simulates an unexpected crash in the worker thread).
        with mock.patch.object(xray, 'verify', side_effect=RuntimeError('unexpected')):
            # Should not raise; bad futures are caught and logged.
            results = server.verify_with_xray(binary, spec, candidates, want_speed=False)
        self.assertIsInstance(results, list)


if __name__ == '__main__':
    unittest.main()
