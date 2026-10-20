"""Unprivileged, isolated Nginx TLS/no-login/CSRF routing acceptance.

No privileged site changes and no public network operations are performed.
"""
from __future__ import annotations
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler

ROOT=Path(__file__).resolve().parents[1]
TEMPLATE=(ROOT/'ops/preview-domain/nginx-app.parser.xdr.ooo.conf').read_text()

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]

class UpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()
    def do_POST(self):
        self.respond()
    def respond(self):
        payload=json.dumps({'service':'isolated-test-upstream','path':self.path}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self,*args):
        pass

class SecurePreviewHost(unittest.TestCase):
    def test_no_site_login_or_credential_setup_is_configured(self):
        for directive in ('auth_basic', 'auth_basic_user_file', 'auth_request'):
            self.assertNotIn(directive, TEMPLATE)
        installer=(ROOT/'ops/preview-domain/install-private-preview.sh').read_text()
        for credential in ('PASSFILE', 'htpasswd', 'read -r -s', 'preview username',
                           'preview password', 'openssl passwd'):
            self.assertNotIn(credential, installer)

    def test_nginx_public_no_login_https_and_post_origin_gate(self):
        with tempfile.TemporaryDirectory(prefix='parser-studio-vhost-') as temp:
            root=Path(temp)
            static=root/'www'
            static.mkdir()
            (static/'index.html').write_text('<title>Parser Studio isolated verification</title>')
            (root/'acme').mkdir()
            cert=root/'cert.pem'
            key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048',
                '-keyout',str(key),'-out',str(cert),'-nodes','-days','1',
                '-subj','/CN=app.parser.xdr.ooo',
                '-addext','subjectAltName=DNS:app.parser.xdr.ooo'],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            backend=ThreadingHTTPServer(('127.0.0.1',0),UpstreamHandler)
            multipass=ThreadingHTTPServer(('127.0.0.1',0),UpstreamHandler)
            servers=[backend,multipass]
            threads=[]
            try:
                for server in servers:
                    thread=threading.Thread(target=server.serve_forever,daemon=True)
                    thread.start()
                    threads.append(thread)
                http_port,https_port=port(),port()
                site=TEMPLATE
                for old,new in [
                    ('listen [::]:80;',''),
                    ('listen 80;',f'listen 127.0.0.1:{http_port};'),
                    ('listen [::]:443 ssl;',''),
                    ('listen 443 ssl;',f'listen 127.0.0.1:{https_port} ssl;'),
                    ('/etc/letsencrypt/live/app.parser.xdr.ooo/fullchain.pem',str(cert)),
                    ('/etc/letsencrypt/live/app.parser.xdr.ooo/privkey.pem',str(key)),
                    ('    include /etc/letsencrypt/options-ssl-nginx.conf;',''),
                    ('    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;',''),
                    ('/var/www/parser-studio-app',str(static)),
                    ('/var/www/parser-studio-acme',str(root/'acme')),
                    ('127.0.0.1:4305',f'127.0.0.1:{backend.server_port}'),
                    ('127.0.0.1:4304',f'127.0.0.1:{multipass.server_port}'),
                ]:
                    site=site.replace(old,new)
                config=root/'nginx.conf'
                config.write_text(
                    f'daemon off; pid {root}/nginx.pid;\n'
                    f'error_log {root}/error.log notice;\n'
                    'events { worker_connections 256; }\n'
                    f'http {{ access_log {root}/access.log; include /etc/nginx/mime.types;\n'+site+'\n}\n'
                )
                check=subprocess.run(['/usr/sbin/nginx','-t','-p',str(root),
                    '-c',str(config)],stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(check.returncode,0,check.stderr.decode(errors='replace'))
                process=subprocess.Popen(['/usr/sbin/nginx','-p',str(root),
                    '-c',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    for _ in range(40):
                        try:
                            with socket.create_connection(('127.0.0.1',https_port),timeout=.2):
                                break
                        except OSError:
                            time.sleep(.1)
                    else:
                        self.fail('Isolated Nginx did not start.')
                    conn=http.client.HTTPConnection('127.0.0.1',http_port,timeout=4)
                    conn.request('GET','/',headers={'Host':'app.parser.xdr.ooo'})
                    response=conn.getresponse()
                    self.assertEqual(response.status,301)
                    self.assertEqual(response.getheader('Location'),
                                     'https://app.parser.xdr.ooo/')
                    response.read()
                    conn.close()

                    client=build_opener(HTTPSHandler(context=ssl._create_unverified_context()))
                    base=f'https://127.0.0.1:{https_port}'
                    # Verify the actual TLS hostname and trust anchor with curl.
                    # This is an isolated fixture CA, not a public TLS bypass.
                    verified=subprocess.run([
                        'curl','--noproxy','*','--cacert',str(cert),
                        '--resolve',f'app.parser.xdr.ooo:{https_port}:127.0.0.1',
                        f'https://app.parser.xdr.ooo:{https_port}/',
                        '--max-time','6'],
                        capture_output=True,text=True,timeout=9)
                    self.assertEqual(verified.returncode,0,verified.stderr)
                    self.assertIn('Parser Studio isolated verification',verified.stdout)
                    wrong_host=subprocess.run([
                        'curl','--noproxy','*','--cacert',str(cert),
                        '--resolve',f'exporter.xdr.ooo:{https_port}:127.0.0.1',
                        f'https://exporter.xdr.ooo:{https_port}/',
                        '--max-time','6'],
                        capture_output=True,text=True,timeout=9)
                    self.assertEqual(wrong_host.returncode,60,wrong_host.stderr)
                    def request(path,method='GET',origin=None):
                        headers={'Host':'app.parser.xdr.ooo'}
                        if origin is not None:
                            headers['Origin']=origin
                        raw=b'{"raw":"{\"action\":\"allow\"}"}' if method=='POST' else None
                        req=Request(base+path,headers=headers,data=raw,method=method)
                        try:
                            with client.open(req,timeout=5) as response:
                                return response.status,response.read(),dict(response.headers)
                        except HTTPError as error:
                            return error.code,error.read(),dict(error.headers)
                    status,body,headers=request('/')
                    self.assertEqual(status,200)
                    self.assertNotIn('WWW-Authenticate',headers)
                    self.assertIn(b'Parser Studio isolated verification',body)
                    self.assertEqual(request('/api/v1/test-lab/session')[0],404)
                    self.assertEqual(request('/api/v1/multipass/preview','POST','https://evil.example')[0],403)
                    self.assertEqual(request('/api/v1/parser-pairs/generate','POST','https://evil.example')[0],403)
                    self.assertEqual(request('/api/v1/multipass/preview','POST','https://app.parser.xdr.ooo')[0],200)
                    self.assertEqual(request('/api/v1/parser-pairs/capabilities')[0],200)
                    self.assertEqual(request('/api/v1/parser-pairs/generate','POST','https://app.parser.xdr.ooo')[0],200)
                finally:
                    process.terminate()
                    process.wait(timeout=8)
            finally:
                for server in servers:
                    server.shutdown()
                    server.server_close()
                for thread in threads:
                    thread.join(timeout=3)

if __name__=='__main__':
    unittest.main()
