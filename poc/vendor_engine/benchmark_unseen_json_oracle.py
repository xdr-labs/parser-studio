"""Independent stdlib JSON source oracle for the new unseen vendor fixture slice."""
from collections import Counter
from pathlib import Path
import hashlib,json
from benchmark_security_sources import reference_json
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

CACHE=Path(__file__).resolve().parent/'.cache/independent_vendor_holdout'

def evaluate():
    manifest=json.loads((CACHE/'manifest.json').read_text())
    totals=Counter();families={};seen=set()
    for item in manifest:
        family=item['path'].split('/')[1]
        counts=families.setdefault(family,Counter())
        data=(CACHE/f"{item['file_id']:02d}.raw").read_bytes()
        if hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('SOURCE_PIN_MISMATCH')
        for raw in data.decode('utf8','strict').splitlines():
            if not raw.strip() or not raw.lstrip().startswith(('{','[')):continue
            sha=hashlib.sha256(raw.encode()).hexdigest()
            if sha in seen:continue
            seen.add(sha)
            try:tree,leaves=reference_json(raw)
            except (ValueError,json.JSONDecodeError):
                counts['unsupported_reference']+=1;totals['unsupported_reference']+=1;continue
            event=parse_security_multipass(raw);assert_source_accounting(event)
            expected=Counter((tuple(x.path),type(x.value).__name__,json.dumps(x.value,ensure_ascii=True,sort_keys=True),x.start_byte,x.end_byte) for x in leaves)
            actual=Counter()
            for span in event.value_spans:
                path=span.source_segments
                if path is None:continue
                value=event.vendor_fields
                try:
                    for key in path:value=value[key]
                    actual[(tuple(path),type(value).__name__,json.dumps(value,ensure_ascii=True,sort_keys=True),span.start_byte,span.end_byte)]+=1
                except (KeyError,IndexError,TypeError):actual[(('INVALID',),'INVALID','INVALID',span.start_byte,span.end_byte)]+=1
            stats=Counter(events=1,fields=len(expected),TP=sum((expected&actual).values()),FP=sum((actual-expected).values()),FN=sum((expected-actual).values()),exact=int(event.vendor_fields==tree and expected==actual),raw_preserved=int(event.raw==raw),false_complete=int(event.status=='SOURCE_PARSED' and (event.vendor_fields!=tree or expected!=actual)))
            totals.update(stats);counts.update(stats)
    tp,fp,fn=totals['TP'],totals['FP'],totals['FN']
    return {'contract':'parser-studio.poc.unseen-json-oracle.v1','evidence_class':'INDEPENDENT_STDLIB_JSON_GOLD_ONLY_NOT_ALL_VENDOR_FAMILIES','total':dict(totals),'f1':round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None,'families':{k:dict(v) for k,v in sorted(families.items()) if v},'raw_published':False}

if __name__=='__main__':print(json.dumps(evaluate(),sort_keys=True))
