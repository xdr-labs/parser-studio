"""Opt-in, loopback-only, stateless Multi-Pass source preview for development.

Never claim native Fluentd or target verification. Do not log source values.
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

MAX_BYTES=65536

def preview(raw:str)->dict:
    if not isinstance(raw,str) or not raw or len(raw.encode('utf8'))>MAX_BYTES:
        raise ValueError('SOURCE_LIMIT')
    event=parse_security_multipass(raw)
    assert_source_accounting(event)
    def region(a:int,b:int)->dict:
        return {'startByte':len(raw[:a].encode('utf8')),'endByte':len(raw[:b].encode('utf8'))}
    return {'contract':'parser-studio.multipass-source-preview.v0.1',
            'status':event.status,'syntax':event.syntax,'sourceSha256':event.raw_sha256,
            'sourceBytes':event.source_bytes,'fields':event.vendor_fields,
            'spans':[{'path':s.path,'startByte':s.start_byte,'endByte':s.end_byte}
                     for s in event.value_spans],
            'residuals':[region(a,b) for a,b in event.unparsed],
            'issues':event.issues[:32],'nativeVerified':False,'targetVerified':False}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,format,*args):pass
    def do_POST(self):
        if self.path!='/api/v1/multipass/preview':self.send_error(404);return
        if self.headers.get('Origin') not in (None,'http://127.0.0.1:5180','http://localhost:5180'):
            self.send_error(403);return
        try:
            length=int(self.headers.get('Content-Length','-1'))
            if not 1<=length<=MAX_BYTES+1024:raise ValueError('SOURCE_LIMIT')
            body=json.loads(self.rfile.read(length).decode('utf8','strict'))
            if not isinstance(body,dict) or set(body)!={'raw'}:raise ValueError('INVALID_REQUEST')
            result=preview(body['raw']);status=200
        except (ValueError,UnicodeError,TypeError,json.JSONDecodeError):
            result={'error':'INVALID_OR_OVERSIZED_SOURCE'};status=422
        except Exception:
            result={'error':'ENGINE_UNAVAILABLE'};status=503
        payload=json.dumps(result,ensure_ascii=True,separators=(',',':')).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers();self.wfile.write(payload)

def serve(port:int=4192):
    if not 1024<=port<=65535:raise ValueError('INVALID_PORT')
    with ThreadingHTTPServer(('127.0.0.1',port),Handler) as server:server.serve_forever()

if __name__=='__main__':
    import argparse
    cli=argparse.ArgumentParser();cli.add_argument('--port',type=int,default=4192)
    serve(cli.parse_args().port)
