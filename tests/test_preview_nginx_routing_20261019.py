"""Unprivileged, isolated Nginx TLS/auth/CSRF routing acceptance.

No privileged site changes and no public network operations are performed.
"""
from __future__ import annotations
import base64
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
TEST_PASS='local-fixture-only-168-char'

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
    def test_nginx_private_https_and_post_origin_gate(self):
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
                '-subj','/CN=app.parser.xdr.ooo'],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            encrypted=subprocess.check_output(
                ['openssl','passwd','-6','-stdin'],input=TEST_PASS.encode(),
                timeout=8).decode().strip()
            password_file=root/'htpasswd'
            password_file.write_text('localtester:'+encrypted+'\n')
            password_file.chmod(0o600)
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
                    ('/etc/nginx/parser-studio-private.htpasswd',str(password_file)),
                    ('/var/www/parser-studio-app',str(static)),
                    ('/var/www/parser-studio-acme',str(root/'acme')),
                    ('127.0.0.1:6571',f'127.0.0.1:{backend.server_port}'),
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
                    def request(path,method='GET',origin=None,credentials=True):
                        headers={'Host':'app.parser.xdr.ooo'}
                        if credentials:
                            encoded=base64.b64encode(('localtester:'+TEST_PASS).encode()).decode()
                            headers['Authorization']='Basic '+encoded
                        if origin is not None:
                            headers['Origin']=origin
                        raw=b'{"raw":"{\"action\":\"allow\"}"}' if method=='POST' else None
                        req=Request(base+path,headers=headers,data=raw,method=method)
                        try:
                            with client.open(req,timeout=5) as response:
                                return response.status,response.read()
                        except HTTPError as error:
                            return error.code,error.read()
                    self.assertEqual(request('/',credentials=False)[0],401)
                    self.assertIn(b'Parser Studio isolated verification',request('/')[1])
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
