"""MP-5 non-regression and selected-standard adjudication benchmark."""
from __future__ import annotations
import dataclasses,json
from pathlib import Path
from benchmark_commercial_security import evaluate as commercial_evaluate
from benchmark_security_sources import read_fixtures
from benchmark_multipass_cef import authored as cef_authored,commercial as cef_commercial,score as cef_score
from benchmark_multipass_leef import authored as leef_authored,_score as leef_score,reference_leef,MANIFEST as LEEF_MANIFEST,CACHE as LEEF_CACHE
from multipass_adjudicator import parse_security_multipass
from security_source import parse_security_source

HERE=Path(__file__).resolve().parent

def evaluate():
    commercial=commercial_evaluate(parse_security_multipass)
    security_total=security_equal=0
    for _item,raws in read_fixtures():
        for raw in raws:
            security_total+=1
            security_equal+=dataclasses.asdict(parse_security_multipass(raw))==dataclasses.asdict(parse_security_source(raw))
    crows,_=cef_commercial();cauth=cef_authored();lauth=leef_authored()
    item=json.loads(LEEF_MANIFEST.read_text())['files'][0]
    external=[reference_leef((LEEF_CACHE/item['name']).read_bytes().decode('utf8','strict').strip('\r\n'))]
    return {
      'contract':'parser-studio.poc.multipass-adjudication.v1',
      'commercial_source':commercial['total'],
      'waf_suricata_records':security_total,'waf_suricata_base_identical':security_equal,
      'cef_commercial':cef_score(crows,parse_security_multipass),'cef_authored':cef_score(cauth,parse_security_multipass),
      'leef_authored':leef_score(lauth,parse_security_multipass),'leef_external_xa6':leef_score(external,parse_security_multipass),
      'runtime_is_acceptance_gate':False,'dictionary_attempted':False,'masking_optimization':False,'native_verified':False}
if __name__=='__main__':
    r=evaluate();(HERE/'multipass-adjudication-summary.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps(r,sort_keys=True))
