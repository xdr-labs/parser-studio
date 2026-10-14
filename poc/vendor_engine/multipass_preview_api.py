"""Opt-in, loopback-only, stateless Multi-Pass source preview for development.

Never claim native Fluentd or target verification. Do not log source values.
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from multipass_adjudicator import parse_security_multipass
from stellar_dictionary import (CEF_DICTIONARY_URL,DICTIONARY_REVISION,OFFICIAL_DICTIONARY_URL_65,
                                OFFICIAL_DICTIONARY_URL_70,normalize_stellar_dictionary)
from source_parse import assert_source_accounting
from visible_redaction import CONTRACT as REDACTION_CONTRACT,assess_visible_redaction

MAX_BYTES=65536

def preview(raw:str)->dict:
    if not isinstance(raw,str) or not raw or len(raw.encode('utf8'))>MAX_BYTES:
        raise ValueError('SOURCE_LIMIT')
    event=parse_security_multipass(raw)
    assert_source_accounting(event)
    def region(a:int,b:int)->dict:
        return {'startByte':len(raw[:a].encode('utf8')),'endByte':len(raw[:b].encode('utf8'))}
    dictionary=normalize_stellar_dictionary(event)
    redaction=assess_visible_redaction(event)
    redaction_view={
        'contract':REDACTION_CONTRACT,
        'assessment':redaction.assessment,
        'sourceOccurrences':redaction.source_occurrences,
        'explicitMaskOccurrences':redaction.explicit_mask_occurrences,
        'unassessedVisibleOccurrences':redaction.unassessed_visible_occurrences,
        'excludedEvent':redaction.assessment=='EXCLUDED_NO_SOURCE_OCCURRENCES',
        'occurrences':[{
            'sourcePath':item.source_path,'occurrence':item.occurrence,
            'markerClass':item.marker_class,
            'startByte':item.start_byte,'endByte':item.end_byte,
        } for item in redaction.occurrences],
        'sourceExtractionPreserved':True,
        'hiddenValueReconstruction':False,
    }
    dictionary_view={
        'contract':'parser-studio.stellar-dictionary-projection.v0.1',
        'dictionaryRevision':DICTIONARY_REVISION,
        'sourceUrls':[OFFICIAL_DICTIONARY_URL_65,OFFICIAL_DICTIONARY_URL_70,CEF_DICTIONARY_URL],
        'mapped':[{'sourcePath':item.source.path,'targetField':item.dictionary_field,
                   'documentedType':item.dictionary_type,
                   'mappingClass':'CEF_STANDARD_ALIAS' if item.rule_id.startswith('cef:') else 'EXACT_DICTIONARY_NAME',
                   'startByte':item.source.start_byte,'endByte':item.source.end_byte}
                  for item in dictionary.mappings],
        'unmappedCount':len(dictionary.unmapped_occurrences),
        'issues':list(dictionary.issues),
        'automaticAliasInference':False,'standardizedAliasMapping':True,
        'sourceExtractionPreserved':True,
        'nativeVerified':False,'targetVerified':False,
    }
    return {'contract':'parser-studio.multipass-source-preview.v0.1',
            'status':event.status,'syntax':event.syntax,'sourceSha256':event.raw_sha256,
            'sourceBytes':event.source_bytes,'fields':event.vendor_fields,
            'spans':[{'path':s.path,'startByte':s.start_byte,'endByte':s.end_byte}
                     for s in event.value_spans],
            'residuals':[region(a,b) for a,b in event.unparsed],
            'issues':event.issues[:32],'dictionary':dictionary_view,
            'redaction':redaction_view,
            'nativeVerified':False,'targetVerified':False}

def allowed_origin(origin:str|None)->bool:
    if origin is None:return True
    try:
        parsed=urlsplit(origin)
        return (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost') and
                parsed.port is not None and 1024<=parsed.port<=65535 and
                parsed.path in ('','/') and not parsed.query and not parsed.fragment and
                parsed.username is None and parsed.password is None)
    except (ValueError,TypeError):
        return False

class Handler(BaseHTTPRequestHandler):
    def log_message(self,format,*args):pass
    def do_POST(self):
        if self.path!='/api/v1/multipass/preview':self.send_error(404);return
        if not allowed_origin(self.headers.get('Origin')):
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
