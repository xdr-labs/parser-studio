"""MP-4 deterministic declared-schema isolation and physical-record ledger."""
from __future__ import annotations
from collections import Counter
import dataclasses,json
from pathlib import Path
from security_source import parse_security_source
from security_cef import parse_security_cef
from security_leef import parse_security_leef
from security_document import parse_security_document
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent

def current(raw):return parse_security_leef(raw,base_parser=lambda text:parse_security_cef(text,base_parser=parse_security_source))

def dataset():
    rows=[];expected_tables={};ordinary=[]
    for n in range(16):
        rows += [r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring']
        idx=len(rows);rows.append(f'u{n}\tallow');expected_tables[idx]={'uid':f'u{n}','action':'allow'}
        foreign=[json.dumps({'action':'BLOCK','labels':[{'name':f'L{n}'}]},separators=(',',':')),
                 f'CEF:0|Vendor|IPS|1|42|Alert|5|src=192.0.2.{n+1} msg="signature {n}"',
                 f'LEEF:2.0|Vendor|IPS|1|42|x7C|src=192.0.2.{n+1}|action=deny',
                 '@cee: '+json.dumps({'event_type':'alert','alert':{'signature_id':n}},separators=(',',':')),
                 f'action=deny src=192.0.2.{n+1}']
        for raw in foreign:ordinary.append((len(rows),raw));rows.append(raw)
        rows.append('#fields\tflow\taction\tbytes')
        bad=len(rows);rows.append(f'f{n}\tdeny\t8')
        rows.append('#types\tstring\tstring\tcount')
        good=len(rows);rows.append(f'f{n}\tdeny\t9');expected_tables[good]={'flow':f'f{n}','action':'deny','bytes':'9'}
        rows.append('#close\t2026-10-14-10-00-00')
        unknown=len(rows);rows.append('#future_security_record\topaque')
        ordinary.append((unknown,rows[unknown]))
    return rows,expected_tables,ordinary

def evaluate():
    rows,tables,ordinary=dataset();doc=parse_security_document(rows,base_parser=current);events=dict(doc.events)
    counts=Counter(physical_records=len(rows),metadata_records=len(doc.metadata_indices),event_records=len(doc.events))
    for idx,expected in tables.items():
        event=events[idx];assert_source_accounting(event)
        counts['declared_rows']+=1;counts['declared_exact_tree']+=event.vendor_fields==expected
        counts['declared_exact_spans']+=len(event.value_spans)==len(expected) and all(event.raw.encode()[s.start_byte:s.end_byte].decode()==event.vendor_fields[s.path] for s in event.value_spans)
    # Rows after #fields but before replacement #types must remain incomplete.
    for i,raw in enumerate(rows):
        if raw.endswith('\tdeny\t8'):
            counts['rotated_without_types']+=1;counts['rotated_without_types_not_complete']+=events[i].status!='SOURCE_PARSED'
    for idx,raw in ordinary:
        event=events[idx];base=current(raw)
        counts['ordinary_records']+=1;counts['ordinary_unchanged']+=dataclasses.asdict(event)==dataclasses.asdict(base)
    ledger=sorted(doc.metadata_indices+[i for i,_ in doc.events])
    counts['physical_record_ledger_exact']=int(ledger==list(range(len(rows))))
    return {'contract':'parser-studio.poc.multipass-document-state.v1','counts':dict(counts),
            'dictionary_attempted':False,'masking_optimization':False,'native_verified':False}
if __name__=='__main__':
    result=evaluate();(HERE/'multipass-document-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(result)
