"""Replay the frozen external ExtraHop-format LEEF documentation example.

No source download, template filling, tab replacement, or hosted AI. The
source page repeats one message twice; the unique original is scored once.
This is a parser-vendor example, NOT an ExtraHop/customer production capture.
"""
from functools import partial
import hashlib
import json
from pathlib import Path
from benchmark_cef_native import ROOT,predict,parse_security_source
from benchmark_leef_upstream import native_reference
from security_leef import parse_security_leef
from cef_reference import score_cef


def main():
    manifest=json.loads((ROOT/'leef-commercial-source-manifest.json').read_text())
    cache=ROOT/'.cache/leef-commercial';freeze=manifest['freeze']
    for name,digest in freeze['module_hashes'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest
    assert hashlib.sha256((cache/'source.html').read_bytes()).hexdigest()==manifest['source_html_sha256']
    raws=[]
    for item in manifest['files']:
        data=(cache/item['name']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256']
        raws.append(data.decode('utf8'))
    assert len(raws)==manifest['unique_leef_records']
    events={name:predict(raws,parser) for name,parser in (
        ('current_main',parse_security_source),
        ('frozen_leef_candidate',partial(parse_security_leef,base_parser=parse_security_source)))}
    private=cache/'frozen-predictions.json';frozen=json.loads(private.read_text())
    assert json.dumps(events,sort_keys=True)==json.dumps(frozen,sort_keys=True)
    # Independent references are evaluated after the frozen predictions.
    refs=[]
    for raw in raws:
        reference=native_reference(raw)
        refs.append({'raw':raw,'tree':reference['tree'],'fields':reference['refs']})
    result={'contract':'parser-studio.external-commercial-leef-score.v1','main_commit':freeze['main_commit'],
       'source_records':len(raws),'occurrences':manifest['leef_example_occurrences'],
       'duplicates':manifest['duplicate_example_occurrences'],'source_kind':manifest['source_kind'],
       'modes':{mode:score_cef(refs,prediction) for mode,prediction in events.items()},
       'candidate_frozen_before_source_acquisition':True,'frozen_predictions_reproduced':True,
       'candidate_module_hashes':freeze['module_hashes'],
       'oracle_sha256':hashlib.sha256((ROOT/'benchmark_leef_upstream.py').read_bytes()).hexdigest(),
       'prediction_sha256':hashlib.sha256(private.read_bytes()).hexdigest(),'source_url':manifest['url'],
       'limitations':['One unique documentation example, not independently verified production traffic.',
          'Duplicate examples count once.','No normalization, recovered values or literal separator substitution.',
          'Not evidence for all vendor versions or other event types.']}
    (ROOT/'leef-commercial-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('EXTERNAL_LEEF_REPLAY',json.dumps(result['modes'],sort_keys=True))

if __name__=='__main__':main()
