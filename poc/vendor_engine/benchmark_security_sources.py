"""Primary security-product source benchmark, separate from prose experiments.

Every reference path/value/type is decoded by the Python standard library;
independent token positions come from a JSON tokenizer, not the PoC decoder.
HTTP header arrays, rule groups, nulls and empty containers stay in the native
source tree. Original fixture values remain only in ignored local caches.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any
from source_parse import parse_source,assert_source_accounting
from security_source import parse_security_source

HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'security-source-manifest.json'
def _unique_object(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('DUPLICATE_REFERENCE_KEY')
        out[key]=value
    return out


DEC=json.JSONDecoder(object_pairs_hook=_unique_object,parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE_REFERENCE_JSON')))


@dataclass(frozen=True)
class ReferenceLeaf:
    path:tuple[str|int,...]
    value:Any
    start_byte:int
    end_byte:int


def reference_json(raw:str)->tuple[Any,list[ReferenceLeaf]]:
    """Independent stdlib scalar tokenization plus a container-path stack."""
    root=DEC.decode(raw)
    if not isinstance(root,(dict,list)):raise ValueError('REFERENCE_COLLECTION_REQUIRED')
    tokens=[];pos=0
    while pos<len(raw):
        if raw[pos] in ' \r\n\t':pos+=1;continue
        if raw[pos] in '{}[]:,':
            tokens.append((raw[pos],None,pos,pos+1));pos+=1;continue
        value,end=DEC.raw_decode(raw,pos)
        if isinstance(value,(dict,list)):raise ValueError('REFERENCE_TOKENIZER_CONTAINER_BUG')
        tokens.append(('value',value,pos,end));pos=end
    stack=[];leaves=[];root_array=isinstance(root,list)
    def next_path():
        if not stack:return ()
        parent=stack[-1]
        return parent['path']+(parent['key'] if parent['kind']=='object' else parent['index'],)
    def finish_value():
        if stack:
            if stack[-1]['kind']=='array':stack[-1]['index']+=1
            else:stack[-1]['key']=None
    for kind,value,start,end in tokens:
        if kind in ('{','['):
            path=next_path()
            stack.append({'kind':'object' if kind=='{' else 'array','path':path,'key':None,'index':0,'expect_key':kind=='{'})
        elif kind in ('}',']'):
            stack.pop();finish_value()
        elif kind==',':
            if stack[-1]['kind']=='object':stack[-1]['expect_key']=True
        elif kind==':':
            stack[-1]['expect_key']=False
        else:
            if stack and stack[-1]['kind']=='object' and stack[-1]['expect_key']:
                if not isinstance(value,str):raise ValueError('REFERENCE_KEY_TYPE')
                stack[-1]['key']=value
            else:
                path=next_path()
                identity=('$array',)+path if root_array else path
                leaves.append(ReferenceLeaf(identity,value,len(raw[:start].encode()),len(raw[:end].encode())))
                finish_value()
    if stack:raise ValueError('REFERENCE_UNBALANCED_STACK')
    return root,leaves


def _tree_leaves(tree,path=()):
    if isinstance(tree,dict):
        for key,value in tree.items():yield from _tree_leaves(value,path+(key,))
    elif isinstance(tree,list):
        for index,value in enumerate(tree):yield from _tree_leaves(value,path+(index,))
    else:yield path,tree


def _cell(path,value):
    return json.dumps(list(path),ensure_ascii=True),json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False)


def _summary(counts:Counter)->dict:
    tp,fp,fn=(counts[k] for k in ('TP','FP','FN'))
    return {**dict(counts),'precision':round(tp/(tp+fp),6) if tp+fp else None,
            'recall':round(tp/(tp+fn),6) if tp+fn else None,
            'f1':round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None}


def read_fixtures():
    manifest=json.loads(MANIFEST.read_text())
    for item in manifest['fixtures']:
        path=HERE/'.cache'/item['cache_path']
        blob=path.read_bytes()
        if len(blob)>4_000_000 or hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('SECURITY_FIXTURE_PIN_OR_BOUND_MISMATCH')
        text=blob.decode('utf8','strict')
        raws=[text] if item.get('framing')=='SINGLE_MULTILINE_JSON_OBJECT' else text.splitlines()
        if any(not raw.strip() for raw in raws):raise ValueError('SECURITY_FIXTURE_BLANK_EVENT_MUST_BE_ACCOUNTED')
        yield item,raws


def evaluate()->dict:
    direct={mode:Counter(TP=0,FP=0,FN=0,exact_span_TP=0,exact_span_FP=0,exact_span_FN=0)
            for mode in ('baseline','candidate')}
    transports={mode:Counter(TP=0,FP=0,FN=0,exact_span_TP=0,exact_span_FP=0,exact_span_FN=0)
                for mode in ('baseline','candidate')}
    fixtures=[];input_counts=Counter(all_direct_events=0,with_explicit_mask_marker_events=0,without_explicit_mask_marker_events=0,explicit_mask_markers=0)
    for item,raws in read_fixtures():
        family={mode:Counter(TP=0,FP=0,FN=0,exact_span_TP=0,exact_span_FP=0,exact_span_FN=0)
                for mode in direct}
        for raw in raws:
            tree,reference=reference_json(raw)
            gold=Counter(_cell(x.path,x.value) for x in reference)
            literal_masks=sum(isinstance(x.value,str) and x.value.upper() in ('REDACTED','<REDACTED>','[REDACTED]','***') for x in reference)
            input_counts['all_direct_events']+=1
            input_counts['with_explicit_mask_marker_events' if literal_masks else 'without_explicit_mask_marker_events']+=1
            input_counts['explicit_mask_markers']+=literal_masks
            for mode,parser in (('baseline',parse_source),('candidate',parse_security_source)):
                out=parser(raw);assert_source_accounting(out)
                observed=Counter(_cell(p,v) for p,v in _tree_leaves(out.vendor_fields))
                expected_spans=Counter((json.dumps(list(x.path)),x.start_byte,x.end_byte) for x in reference)
                actual_spans=Counter((json.dumps(list(x.source_segments)) if x.source_segments is not None else 'NO_IDENTITY',x.start_byte,x.end_byte) for x in out.value_spans)
                counts=Counter(events=1,gold_fields=len(reference),TP=sum((gold&observed).values()),
                    FP=sum((observed-gold).values()),FN=sum((gold-observed).values()),
                    exact_span_TP=sum((expected_spans&actual_spans).values()),
                    exact_span_FP=sum((actual_spans-expected_spans).values()),exact_span_FN=sum((expected_spans-actual_spans).values()),
                    original_records_preserved=int(out.raw==raw),exact_original_tree_events=int(out.vendor_fields==tree),
                    source_parsed_events=int(out.status=='SOURCE_PARSED'))
                family[mode].update(counts);direct[mode].update(counts)
            # CEE is a documented Suricata output option. Transport cases are
            # labeled derived fixtures, NEVER counted again as original events.
            if not item['id'].startswith('suricata'):continue
            for prefix in ('@cee: ','Oct 14 10:11:12 sensor suricata: @cee: ',
                           '<134>1 2026-10-14T10:11:12Z sensor suricata 42 - - @cee: '):
                framed=prefix+raw;offset=len(prefix.encode());wrapped=not prefix.startswith('@cee:')
                for mode,parser in (('baseline',parse_source),('candidate',parse_security_source)):
                    out=parser(framed);assert_source_accounting(out)
                    payload=out.vendor_fields.get('body',{}) if wrapped else out.vendor_fields
                    observed=Counter(_cell(p,v) for p,v in _tree_leaves(payload))
                    expected_spans=Counter((json.dumps(list(x.path)),x.start_byte+offset,x.end_byte+offset) for x in reference)
                    actual_spans=Counter()
                    for span in out.value_spans:
                        if wrapped and not span.path.startswith('body.'):continue
                        identity=span.source_segments
                        if wrapped and identity is not None:identity=identity[1:]
                        actual_spans[(json.dumps(list(identity)) if identity is not None else 'NO_IDENTITY',span.start_byte,span.end_byte)]+=1
                    transports[mode].update(events=1,gold_fields=len(reference),
                        TP=sum((gold&observed).values()),FP=sum((observed-gold).values()),FN=sum((gold-observed).values()),
                        exact_span_TP=sum((expected_spans&actual_spans).values()),exact_span_FP=sum((actual_spans-expected_spans).values()),
                        exact_span_FN=sum((expected_spans-actual_spans).values()),
                        original_records_preserved=int(out.raw==framed),exact_original_tree_events=int(payload==tree),
                        source_parsed_events=int(out.status=='SOURCE_PARSED'))
        fixtures.append({'fixture_id':item['id'],'source_class':item.get('source_class','UPSTREAM_TEST_FIXTURE'),
                         'events':len(raws),'results':{k:_summary(v) for k,v in family.items()}})
    return {'contract':'parser-studio.poc.security-source-benchmark.v1',
            'scope':'SECURITY_SYSTEM_SOURCE_FIELDS_ONLY_NOT_SENTENCE_MINING',
            'baseline_revision':'2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03',
            'candidate_sha256':hashlib.sha256((HERE/'security_source.py').read_bytes()).hexdigest(),
            'corpus_manifest_sha256':hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
            'direct_original_security_events':{k:_summary(v) for k,v in direct.items()},
            'documented_cee_transport_variants':{k:_summary(v) for k,v in transports.items()},
            'transport_evidence_class':'DERIVED_FRAMING_VARIANTS_NOT_ADDITIONAL_ORIGINAL_TRAFFIC',
            'source_marker_accounting':dict(input_counts),'excluded_events':0,
            'fixtures':fixtures,'dictionary_attempted':False,'masking_optimization':False,
            'native_verified':False,'product_integration':False,
            'limitations':['Upstream integration fixtures and official AWS examples are not customer-production or universal accuracy.',
                           'Absence of a literal masking marker does not prove a fixture was never anonymized upstream.',
                           'Every source field, including payload and message, is preserved; no security role is guessed.',
                           'Raw logs remain in ignored research caches; only counters and provenance are published.']}


if __name__=='__main__':
    result=evaluate()
    (HERE/'security-source-summary.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('SECURITY_DIRECT',result['direct_original_security_events'])
    print('SECURITY_CEE_DERIVED',result['documented_cee_transport_variants'])
    print('MASK_MARKER_ACCOUNTING',result['source_marker_accounting'])
