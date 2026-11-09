"""Opt-in, loopback-only, stateless Multi-Pass source preview for development.

Never claim native Fluentd or target verification. Do not log source values.
"""
from __future__ import annotations
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from multipass_adjudicator import parse_security_multipass
from bounded_funnel import parse_security_funnel,run_funnel_batch
from security_framing import parse_security_batch
from stellar_dictionary import (CEF_DICTIONARY_URL,DICTIONARY_REVISION,OFFICIAL_DICTIONARY_URL_65,
                                OFFICIAL_DICTIONARY_URL_70,normalize_stellar_dictionary)
from source_parse import assert_source_accounting
from visible_redaction import CONTRACT as REDACTION_CONTRACT,assess_visible_redaction

MAX_BYTES=65536
# Only the original decoded source is capped at 64 KiB. JSON escaping of an
# accepted source can expand each byte to as many as six ASCII bytes (\u0000).
# Bound the transport envelope separately; preview()/preview_batch() still
# reject any decoded source larger than MAX_BYTES before parsing.
MAX_HTTP_JSON_BODY_BYTES=MAX_BYTES*6+1024

def _preview_event(raw:str,event)->dict:
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
                   'mappingClass':('CEF_STANDARD_ALIAS' if item.rule_id.startswith('cef:')
                                   else 'EXPLICIT_SOURCE_ALIAS' if item.rule_id.startswith('explicit-source:')
                                   else 'EXACT_DICTIONARY_NAME'),
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


def preview(raw:str)->dict:
    if not isinstance(raw,str) or not raw or len(raw.encode('utf8'))>MAX_BYTES:
        raise ValueError('SOURCE_LIMIT')
    return _preview_event(raw,parse_security_funnel(raw))


def preview_batch(raw:str)->dict:
    if not isinstance(raw,str) or not raw or len(raw.encode('utf8'))>MAX_BYTES:
        raise ValueError('SOURCE_LIMIT')
    batch=parse_security_batch(raw,max_events=500,max_bytes=MAX_BYTES,
                               parser=parse_security_multipass)
    funnel=run_funnel_batch([frame.raw for frame in batch.frames])
    # The batch framer is authoritative for malformed/ambiguous record
    # boundaries. Never reparse its fail-closed events into apparent success.
    selected=[
        frame.event if any(issue.startswith(('FRAMING_','SCHEMA_')) for issue in frame.event.issues)
        else funnel.selected[index]
        for index,frame in enumerate(batch.frames)
    ]
    return {
        'contract':'parser-studio.multipass-source-batch-preview.v0.1',
        'sourceSha256':hashlib.sha256(raw.encode('utf8')).hexdigest(),
        'sourceBytes':len(raw.encode('utf8')),
        'eventCount':len(batch.frames),
        'events':[{
            'index':index,
            'startByte':frame.start_byte,
            'endByte':frame.end_byte,
            'preview':_preview_event(frame.raw,selected[index]),
        } for index,frame in enumerate(batch.frames)],
        'separators':[{
            'startByte':separator.start_byte,
            'endByte':separator.end_byte,
            'kind':separator.kind,
        } for separator in batch.separators],
        'nativeVerified':False,
        'targetVerified':False,
    }

def allowed_origin(origin:str|None)->bool:
    if origin is None:return True
    try:
        parsed=urlsplit(origin)
        if (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost') and
                parsed.port is not None and 1024<=parsed.port<=65535 and
                parsed.path in ('','/') and not parsed.query and not parsed.fragment and
                parsed.username is None and parsed.password is None):
            return True
        # An explicitly configured, exact HTTPS origin is allowed only when a
        # separately authenticated reverse proxy gates browser/API traffic.
        # Never use suffix matching, wildcard hosts or forwarded headers here.
        trusted=os.environ.get('PARSER_STUDIO_TRUSTED_ORIGIN','')
        configured=urlsplit(trusted) if trusted else None
        return bool(configured and origin==trusted and
                    configured.scheme=='https' and configured.hostname and
                    configured.port is None and configured.path in ('','/') and
                    not configured.query and not configured.fragment and
                    configured.username is None and configured.password is None)
    except (ValueError,TypeError):
        return False

class Handler(BaseHTTPRequestHandler):
    def log_message(self,format,*args):pass
    def do_GET(self):
        if self.path!='/health':
            self.send_error(404);return
        payload=b'{"status":"ok","contract":"parser-studio.multipass-source-preview.v0.1"}'
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers();self.wfile.write(payload)
    def do_POST(self):
        if self.path not in ('/api/v1/multipass/preview','/api/v1/multipass/preview-batch'):
            self.send_error(404);return
        if not allowed_origin(self.headers.get('Origin')):
            self.send_error(403);return
        try:
            length=int(self.headers.get('Content-Length','-1'))
            if not 1<=length<=MAX_HTTP_JSON_BODY_BYTES:raise ValueError('SOURCE_LIMIT')
            body=json.loads(self.rfile.read(length).decode('utf8','strict'))
            if not isinstance(body,dict) or set(body)!={'raw'}:raise ValueError('INVALID_REQUEST')
            result=(preview_batch(body['raw']) if self.path.endswith('preview-batch')
                    else preview(body['raw']));status=200
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
