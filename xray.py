"""Real Xray-core integration: run a user's own config against a candidate IP.

A TLS handshake only proves the edge answers. This module proves the *config*
actually carries traffic through that edge, which is the thing the user cares about.
"""

import base64
import binascii
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Where a request is sent to prove the tunnel really carries traffic.
PROBE_HOST = 'www.gstatic.com'
PROBE_PATH = '/generate_204'
PROBE_EXPECT = 204
PROBE_TARGETS = (
    ('www.gstatic.com', '/generate_204'),
    ('cp.cloudflare.com', '/generate_204'),
    ('www.google.com', '/generate_204'),
)

# Not every exit can reach every host — Worker-based configs often refuse Cloudflare's
# own speedtest — so try a few until one actually delivers bytes.
SPEED_TARGETS = (
    ('speed.cloudflare.com', '/__down?bytes=25000000'),
    ('proof.ovh.net', '/files/10Mb.dat'),
    ('cachefly.cachefly.net', '/10mb.test'),
)
SPEED_BUDGET_SEC = 6.0
SPEED_MIN_BYTES = 64 * 1024

STARTUP_TIMEOUT = 6.0
SOCKS_BASE_PORT = 21080

HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                         r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
SUPPORTED_NETWORKS = {'tcp', 'ws', 'grpc', 'gun', 'h2', 'http', 'httpupgrade', 'xhttp'}
SUPPORTED_SECURITY = {'none', 'tls', 'reality'}


def find_xray():
    """Locate the xray binary. Installer drops it in ./bin, but PATH works too."""
    override = os.environ.get('XRAY_BIN')
    candidates = [override] if override else []
    candidates += [
        os.path.join(BASE_DIR, 'bin', 'xray'),
        os.path.join(BASE_DIR, 'xray'),
    ]
    prefix = os.environ.get('PREFIX')
    if prefix:
        candidates.append(os.path.join(prefix, 'bin', 'xray'))
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which('xray')


def xray_version(path=None):
    path = path or find_xray()
    if not path:
        return None
    try:
        out = subprocess.run([path, 'version'], capture_output=True, timeout=6, text=True)
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else None
    except Exception:
        return None


def _b64_pad(value):
    return value + '=' * (-len(value) % 4)


def _qs(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}


def _valid_hostname(value):
    value = (value or '').strip()
    return bool(value and HOSTNAME_RE.fullmatch(value))


def _validate_spec(spec):
    if not _valid_hostname(spec['host']):
        raise ValueError('missing or invalid server address')
    if not 1 <= spec['port'] <= 65535:
        raise ValueError('port out of range')
    if spec['protocol'] in ('vless', 'vmess') and not spec['uuid']:
        raise ValueError('missing user id')
    if spec['protocol'] == 'trojan' and not spec['password']:
        raise ValueError('missing password')
    if spec['network'] not in SUPPORTED_NETWORKS:
        raise ValueError('unsupported transport')
    if spec['security'] not in SUPPORTED_SECURITY:
        raise ValueError('unsupported security')
    if spec['security'] in ('tls', 'reality') and not _valid_hostname(spec['sni']):
        raise ValueError('missing or invalid sni')
    if spec['security'] == 'reality' and not spec['public_key']:
        raise ValueError('missing reality public key')
    return spec


def parse_link(uri):
    """Turn a vless/vmess/trojan share link into a normalised outbound spec.

    Raises ValueError with a Persian-safe short reason the UI can show.
    """
    uri = (uri or '').strip()
    if not uri:
        raise ValueError('empty config')

    if uri.lower().startswith('vmess://'):
        try:
            raw = base64.urlsafe_b64decode(_b64_pad(uri[8:])).decode('utf-8')
            cfg = json.loads(raw)
            port = int(cfg.get('port') or 443)
            alter_id = int(cfg.get('aid') or 0)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise ValueError('bad vmess payload')
        host = str(cfg.get('add') or '').strip()
        net = str(cfg.get('net') or 'tcp').lower()
        security = str(cfg.get('tls') or '').lower()
        return _validate_spec({
            'protocol': 'vmess',
            'host': host,
            'port': port,
            'uuid': str(cfg.get('id') or ''),
            'alter_id': alter_id,
            'network': net,
            'security': 'reality' if security == 'reality' else ('tls' if security == 'tls' else 'none'),
            'sni': str(cfg.get('sni') or cfg.get('host') or host),
            'ws_host': str(cfg.get('host') or host),
            'path': str(cfg.get('path') or '/'),
            'service_name': str(cfg.get('path') or ''),
            'flow': '',
            'fingerprint': str(cfg.get('fp') or ''),
            'public_key': '',
            'short_id': '',
            'password': '',
        })

    url = urllib.parse.urlparse(uri)
    scheme = url.scheme.lower()
    if scheme not in ('vless', 'trojan'):
        raise ValueError('unsupported protocol')
    if not url.hostname or not url.username:
        raise ValueError('malformed link')

    q = _qs(url)
    host = url.hostname
    security = (q.get('security') or 'none').lower()
    sni = q.get('sni') or q.get('peer') or q.get('host') or host
    try:
        port = int(url.port or 443)
    except ValueError:
        raise ValueError('port out of range')
    return _validate_spec({
        'protocol': scheme,
        'host': host,
        'port': port,
        'uuid': urllib.parse.unquote(url.username) if scheme == 'vless' else '',
        'password': urllib.parse.unquote(url.username) if scheme == 'trojan' else '',
        'alter_id': 0,
        'network': (q.get('type') or 'tcp').lower(),
        'security': security,
        'sni': sni,
        'ws_host': q.get('host') or sni,
        'path': urllib.parse.unquote(q.get('path') or '/'),
        'service_name': urllib.parse.unquote(q.get('serviceName') or ''),
        'flow': q.get('flow') or '',
        'fingerprint': q.get('fp') or 'chrome',
        'public_key': q.get('pbk') or '',
        'short_id': q.get('sid') or '',
    })


def _stream_settings(spec):
    net = spec['network'] or 'tcp'
    stream = {'network': net}

    if net == 'ws':
        stream['wsSettings'] = {'path': spec['path'] or '/',
                                'headers': {'Host': spec['ws_host'] or spec['sni']}}
    elif net in ('grpc', 'gun'):
        stream['network'] = 'grpc'
        stream['grpcSettings'] = {'serviceName': spec['service_name'] or spec['path'].strip('/')}
    elif net in ('h2', 'http'):
        stream['network'] = 'h2'
        stream['httpSettings'] = {'path': spec['path'] or '/',
                                  'host': [spec['ws_host'] or spec['sni']]}
    elif net == 'httpupgrade':
        stream['httpupgradeSettings'] = {'path': spec['path'] or '/',
                                         'host': spec['ws_host'] or spec['sni']}
    elif net == 'xhttp':
        stream['xhttpSettings'] = {'path': spec['path'] or '/',
                                   'host': spec['ws_host'] or spec['sni']}

    if spec['security'] == 'reality':
        stream['security'] = 'reality'
        stream['realitySettings'] = {
            'serverName': spec['sni'],
            'fingerprint': spec['fingerprint'] or 'chrome',
            'publicKey': spec['public_key'],
            'shortId': spec['short_id'],
        }
    elif spec['security'] == 'tls':
        stream['security'] = 'tls'
        stream['tlsSettings'] = {
            'serverName': spec['sni'],
            'allowInsecure': False,
            'fingerprint': spec['fingerprint'] or 'chrome',
        }
    else:
        stream['security'] = 'none'
    return stream


def build_config(spec, ip, socks_port, port=None):
    """Xray config whose outbound dials `ip` while still presenting the real SNI/Host.

    That substitution is the whole point: everything the server checks stays
    identical, only the edge we route through changes.
    """
    target_port = int(port or spec['port'])
    stream = _stream_settings(spec)

    if spec['protocol'] == 'trojan':
        outbound_settings = {'servers': [{'address': ip, 'port': target_port,
                                          'password': spec['password']}]}
    elif spec['protocol'] == 'vmess':
        outbound_settings = {'vnext': [{'address': ip, 'port': target_port,
                                        'users': [{'id': spec['uuid'],
                                                   'alterId': spec['alter_id'],
                                                   'security': 'auto'}]}]}
    else:
        user = {'id': spec['uuid'], 'encryption': 'none'}
        if spec['flow']:
            user['flow'] = spec['flow']
        outbound_settings = {'vnext': [{'address': ip, 'port': target_port, 'users': [user]}]}

    return {
        'log': {'loglevel': 'error'},
        'inbounds': [{
            'tag': 'socks-in',
            'listen': '127.0.0.1',
            'port': socks_port,
            'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': False},
        }],
        'outbounds': [{
            'tag': 'proxy',
            'protocol': spec['protocol'],
            'settings': outbound_settings,
            'streamSettings': stream,
        }],
    }


class XrayTunnel:
    """Runs one xray process with a local SOCKS inbound, for one candidate IP."""

    def __init__(self, binary, spec, ip, socks_port, port=None):
        self.binary = binary
        self.config = build_config(spec, ip, socks_port, port)
        self.socks_port = socks_port
        self.proc = None
        self._cfg_path = None

    def __enter__(self):
        try:
            fd, self._cfg_path = tempfile.mkstemp(suffix='.json', prefix='zeus-xray-')
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                json.dump(self.config, fh)
            # Xray errors are represented by its exit status. Do not leave a PIPE
            # unread: a noisy process must never deadlock the verifier.
            self.proc = subprocess.Popen(
                [self.binary, 'run', '-c', self._cfg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + STARTUP_TIMEOUT
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise RuntimeError('xray exited on startup')
                try:
                    with socket.create_connection(('127.0.0.1', self.socks_port), timeout=0.3):
                        return self
                except OSError:
                    time.sleep(0.08)
            raise RuntimeError('xray socks port never opened')
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass  # process will be reaped by the OS eventually
        if self._cfg_path:
            try:
                os.unlink(self._cfg_path)
            except OSError:
                pass
            self._cfg_path = None
        self.proc = None
        return False


def socks_connect(socks_port, host, port, timeout):
    """Minimal SOCKS5 CONNECT so we stay dependency-free like the rest of the project."""
    sock = socket.create_connection(('127.0.0.1', socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b'\x05\x01\x00')
        greeting = _recv_exact(sock, 2)
        if greeting != b'\x05\x00':
            raise OSError('socks greeting refused')

        try:
            target = host.encode('idna')
        except (UnicodeError, UnicodeDecodeError) as exc:
            raise OSError(f'invalid hostname for SOCKS5: {exc}') from exc
        if len(target) > 255:
            raise OSError(f'hostname too long for SOCKS5 ({len(target)} bytes, max 255)')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(target)]) + target + struct.pack('>H', port))

        head = _recv_exact(sock, 4)
        if len(head) < 4 or head[1] != 0x00:
            raise OSError(f'socks connect failed (code {head[1] if len(head) > 1 else "?"})')
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        else:
            raise OSError('socks returned an unknown address type')
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError('connection closed during SOCKS handshake')
        data.extend(chunk)
    return bytes(data)


def _https_get(socks_port, host, path, timeout, drain_seconds=None):
    """GET over TLS through the SOCKS proxy. Returns (status, bytes_drained, seconds)."""
    sock = socks_connect(socks_port, host, 443, timeout)
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=host) as tls:
            tls.settimeout(timeout)
            req = (f'GET {path} HTTP/1.1\r\nHost: {host}\r\n'
                   'User-Agent: Mozilla/5.0 (Zeus-Scanner)\r\n'
                   'Accept: */*\r\nConnection: close\r\n\r\n')
            tls.sendall(req.encode('ascii'))

            head = b''
            while b'\r\n\r\n' not in head and len(head) < 32768:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                head += chunk
            if not head.startswith(b'HTTP/1.') and not head.startswith(b'HTTP/2'):
                raise OSError('no http response through tunnel')
            status = int(head.split(b' ', 2)[1])

            if drain_seconds is None:
                return status, 0, 0.0

            body = len(head) - (head.find(b'\r\n\r\n') + 4 if b'\r\n\r\n' in head else len(head))
            # The clock starts once bytes are actually arriving; connect and TLS cost
            # belongs to latency, not to throughput.
            started = time.monotonic()
            deadline = started + drain_seconds
            while time.monotonic() < deadline:
                tls.settimeout(max(0.1, min(timeout, deadline - time.monotonic())))
                chunk = tls.recv(65536)
                if not chunk:
                    break
                body += len(chunk)
            return status, body, time.monotonic() - started
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _reason(exc):
    """OpenSSL/socket errors are unreadable in a UI, so map them to a short cause."""
    text = f'{exc.__class__.__name__}: {exc}'.lower()
    if 'timed out' in text or 'timeout' in text:
        return 'timeout'
    if 'refused' in text:
        return 'refused'
    if 'reset' in text or 'eof' in text or 'broken pipe' in text:
        return 'rejected'
    if 'socks connect failed' in text:
        return 'unreachable'
    if 'unreachable' in text or 'no route' in text:
        return 'unreachable'
    if 'xray exited' in text or 'never opened' in text:
        return 'bad config'
    return str(exc) or exc.__class__.__name__


def _measure_speed(socks_port, timeout):
    """Download through the live tunnel. Returns KB/s, or None if no target delivered."""
    for host, path in SPEED_TARGETS:
        try:
            _, body, elapsed = _https_get(socks_port, host, path, timeout,
                                          drain_seconds=SPEED_BUDGET_SEC)
        except Exception:
            continue
        if body >= SPEED_MIN_BYTES and elapsed > 0:
            return int(body / 1024 / elapsed)
    return None


def verify(binary, spec, ip, socks_port, port=None, timeout=8.0, want_speed=False):
    """Bring the tunnel up for one IP and prove traffic flows. Never raises."""
    started = time.monotonic()
    try:
        with XrayTunnel(binary, spec, ip, socks_port, port):
            handshake_ms = int((time.monotonic() - started) * 1000)
            status = None
            for probe_host, probe_path in PROBE_TARGETS:
                try:
                    candidate_status, _, _ = _https_get(
                        socks_port, probe_host, probe_path, timeout)
                except Exception:
                    continue
                if candidate_status == PROBE_EXPECT or 200 <= candidate_status < 400:
                    status = candidate_status
                    break
            if status is None:
                return {'ok': False, 'error': 'probe destinations unreachable'}

            result = {'ok': True, 'latency': handshake_ms, 'status': status, 'speed': None}
            if want_speed:
                result['speed'] = _measure_speed(socks_port, timeout)
            return result
    except Exception as exc:
        return {'ok': False, 'error': _reason(exc)}


if __name__ == '__main__':
    binary = find_xray()
    print('xray:', binary, '|', xray_version(binary))
    if len(sys.argv) > 2:
        spec = parse_link(sys.argv[1])
        print(json.dumps(verify(binary, spec, sys.argv[2], SOCKS_BASE_PORT, want_speed=True),
                         ensure_ascii=False))
