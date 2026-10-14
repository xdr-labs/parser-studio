"""Current-engine comparison of original CEF and authored encoding conformance.

Original source uses event.original, never an already decoded message field.
The scalar oracle is independent of all parsers. Authored expected source
spelling/values/spans are assembled separately and must agree with the oracle.
Only aggregate evidence is published. All input and prediction values stay local.
"""
from __future__ import annotations
import dataclasses
from functools import partial
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
CURRENT='c2f464444a7aa899bd8b251507234720e4cbdde2'
ENGINE=(ROOT/'.cache/current-c2f4644/poc/vendor_engine').resolve()
sys.path.insert(0,str(ENGINE))
from source_parse import assert_source_accounting
from security_source import parse_security_source
sys.path.insert(0,str(ROOT))
from cef_reference import reference_cef,score_cef,HEADER_NAMES
from security_cef import parse_security_cef
from security_leef import parse_security_leef
from security_document import parse_security_document

PARSERS={'current_main':parse_security_source,'cef_standard_candidate':partial(parse_security_cef,base_parser=parse_security_source)}


def encoded_header(value):return value.replace('\\','\\\\').replace('|','\\|')
def encoded_extension(value):return value.replace('\\','\\\\').replace('=','\\=').replace('\n','\\n').replace('\r','\\r')


def authored():
    result=[]
    for i in range(12):
        variants={
          'literal_double_quotes':[('msg',f'"IPS match {i}"'),('act','deny')],
          'literal_single_quotes':[('msg',f"'signature {i}'"),('act','deny')],
          'literal_quote_suffix':[('msg',f'"IPS{i}"suffix'),('act','deny')],
          'trailing_spaces':[('msg',f'IPS {i}   '),('act','deny')],
          'leading_spaces':[('msg',f'  IPS {i}'),('act','deny')],
          'encoded_payload':[('msg',f'Zoë{i}\nrule=value | boundary'),('act','deny')],
          'repeated_empty':[('tag','ips'),('tag',str(i)),('empty',''),('act','deny')],
          'ordinary_control':[('src','192.0.2.'+str(i+1)),('spt',str(1024+i)),('act','deny')],
        }
        for family,values in variants.items():
            raw='CEF:';tree={'cef_header':{},'cef_extension':{}};fields=[]
            for name,value in zip(HEADER_NAMES,('0','Example','IPS','1','42','Rule | match','7')):
                a=len(raw.encode());raw+=encoded_header(value);b=len(raw.encode());raw+='|'
                fields.append((('cef_header',name),value,a,b));tree['cef_header'][name]=value
            for j,(key,value) in enumerate(values):
                if j:raw+=' '
                raw+=key+'=';a=len(raw.encode());raw+=encoded_extension(value);b=len(raw.encode())
                fields.append((('cef_extension',key),value,a,b));target=tree['cef_extension']
                if key in target:
                    old=target[key];target[key]=old+[value] if isinstance(old,list) else [old,value]
                else:target[key]=value
            ref={'raw':raw,'fields':fields,'tree':tree}
            oracle=reference_cef(raw)
            if oracle!=ref:raise AssertionError('ENCODER_AND_INDEPENDENT_ORACLE_DISAGREE')
            result.append((family,ref))
    return result


def predict(raws,parser):
    out=[]
    for raw in raws:
        try:
            event=parser(raw);assert event.raw==raw;assert_source_accounting(event)
            data=dataclasses.asdict(event);data['status']=event.status;out.append(data)
        except Exception as exc:out.append({'raw':raw,'error':type(exc).__name__})
    return out


def collect_originals():
    manifest=json.loads((ROOT/'cef-leef-source-manifest.json').read_text());refs=[];groups={}
    for item in manifest['files']:
        data=(ROOT/'.cache/cef-leef'/item['name']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==item['sha256']
        raws=[row['event']['original'] for row in json.loads(data)['events']]
        assert len(raws)==item['records']
        group=[reference_cef(raw) for raw in raws];groups[item['name']]=group;refs.extend(group)
    return refs,groups


def main():
    import source_parse,security_source
    assert Path(source_parse.__file__).resolve().parent==ENGINE
    assert Path(security_source.__file__).resolve().parent==ENGINE
    integrity={}
    for name in ('engine.py','source_parse.py','structured_source.py','security_source.py','source_kv.py','java_source.py','residual_kv.py'):
        expected=subprocess.check_output(['git','show',f'{CURRENT}:poc/vendor_engine/{name}'],cwd=ROOT)
        assert (ENGINE/name).read_bytes()==expected
        integrity[name]=hashlib.sha256(expected).hexdigest()
    original,groups=collect_originals();synthetic=authored();valid=[r for _,r in synthetic]
    results={};predictions={}
    for label,rows in (('commercial_originals',original),('authored_conformance',valid)):
        results[label]={};predictions[label]={}
        for mode,parser in PARSERS.items():
            events=predict([r['raw'] for r in rows],parser);predictions[label][mode]=events
            results[label][mode]=score_cef(rows,events)
    historical=json.loads((ROOT/'.cache/cef-leef/frozen-source-predictions.json').read_text())
    frozen=[e for name in groups for e in historical[name]]
    assert json.dumps(frozen,sort_keys=True)==json.dumps(predictions['commercial_originals']['current_main'],sort_keys=True),'FROZEN_SOURCE_PREDICTIONS_CHANGED'
    per_family={family:{mode:score_cef([r for f,r in synthetic if f==family],predict([r['raw'] for f,r in synthetic if f==family],parser)) for mode,parser in PARSERS.items()} for family in sorted({f for f,_ in synthetic})}
    commercial={name:{mode:score_cef(refs,predict([r['raw'] for r in refs],parser)) for mode,parser in PARSERS.items()} for name,refs in groups.items()}
    derived=[];framed_predictions={m:[] for m in PARSERS}
    prefixes=('<134>Oct 14 12:00:00 sensor ips: ','<134>1 2026-10-14T12:00:00Z sensor ips 1 ALERT - ','Oct 14 12:00:00 sensor ips: ')
    for prefix in prefixes:
        offset=len(prefix.encode())
        for ref in valid:
            raw=prefix+ref['raw'];derived.append({'raw':raw,'tree':ref['tree'],'fields':[(p,v,a+offset,b+offset) for p,v,a,b in ref['fields']]})
            for mode,parser in PARSERS.items():
                event=predict([raw],parser)[0]
                if 'error' not in event:
                    event['vendor_fields']=event['vendor_fields'].get('body',{})
                    event['value_spans']=[{**s,'path':s['path'][5:]} for s in event['value_spans'] if s['path'].startswith('body.')]
                framed_predictions[mode].append(event)
    results['derived_syslog_bodies']={mode:score_cef(derived,events) for mode,events in framed_predictions.items()}
    # These malformed records have no complete-field oracle and stay separate.
    invalid=[r['raw']+'\\' for r in valid[:12]]+[r['raw']+'\nextra' for r in valid[:12]]
    results['malformed_controls']={}
    for mode,parser in PARSERS.items():
        events=predict(invalid,parser)
        results['malformed_controls'][mode]={'records':len(events),'raw_preserved':sum(e['raw']==r for e,r in zip(events,invalid)),
          'exceptions':sum('error' in e for e in events),'falsely_complete':sum(e.get('status')=='SOURCE_PARSED' for e in events)}
    # Existing security records exercise the combined addon and document path.
    manifest=json.loads((ROOT/'security-source-manifest.json').read_text());raws=[]
    for item in manifest['files']:
        data=(ROOT/'.cache/security-logs'/item['local_name']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256'];raws.extend(data.decode().splitlines())
    combined=partial(parse_security_cef,base_parser=partial(parse_security_leef,base_parser=parse_security_source))
    doc=parse_security_document(raws,base_parser=combined)
    assert not doc.metadata_indices and len(doc.events)==len(raws)
    invariant=sum(dataclasses.asdict(event)==dataclasses.asdict(parse_security_source(raws[i])) for i,event in doc.events)
    private=ROOT/'.cache/cef-native-current-predictions.json';private.write_text(json.dumps(predictions,ensure_ascii=True,sort_keys=True))
    result={'contract':'parser-studio.cef-native-comparison.v1','baseline_commit':CURRENT,'entrypoint':'security_source.parse_security_source',
      'frozen_original_predictions_identical':True,'results':results,'commercial_groups':commercial,'authored_groups':per_family,
      'existing_security_invariance':{'records':len(raws),'unchanged':invariant},'baseline_integrity':integrity,
      'module_hashes':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('cef_reference.py','security_cef.py','benchmark_cef_native.py')},
      'prediction_sha256':hashlib.sha256(private.read_bytes()).hexdigest(),'dictionary_attempted':False,'native_verified':False,'product_integrated':False,
      'limitations':['22 upstream commercial source records are regression fixtures, not verified production captures; redaction unassessed.',
      'Authored96 and derived288 measure CEF-standard conformance, not blind vendor generalization.',
      'Derived syslog scores cover CEF bodies; envelope fields are outside that oracle.',
      'Quoted-KV dialects may differ; this strict CEF candidate is not approved as a universal product default.',
      '24 malformed controls are separately accounted and not successful extraction.']}
    (ROOT/'cef-native-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for group,value in results.items():print(group,json.dumps(value,sort_keys=True))
    print('SECURITY_OUTPUT_INVARIANCE',invariant,len(raws))

if __name__=='__main__':main()
