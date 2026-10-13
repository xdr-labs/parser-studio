"""Independent exact vendor source-field value/identity benchmark.

Gold is produced from the pinned raw (NOT the PoC parser's output) by
independent stdlib JSON, CSV and POSIX shlex decoders. A correct source field
requires its original key/position, original typed value and full event
identity. No ECS or Stellar semantic field mapping is attempted.

This qualifies only the eight already collected well-formed upstream
sources, not unseen vendors, malformed logs, or runtime Ruby/CONF support.
"""
from __future__ import annotations
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import shlex
from typing import Any

from corpus import entries,load_case
from engine import PRI,BSD
from source_parse import parse_source,assert_source_accounting
from source_field_metrics import SourceField,SourceRecord,score_source_fields

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"


def _flatten(value:Any,path:str="")->list[SourceField]:
    """Unambiguous source paths including nested arrays/dotted vendor keys."""
    if isinstance(value,dict):
        out=[]
        for key,child in value.items():
            escaped=str(key).replace("~","~0").replace("/","~1")
            out.extend(_flatten(child,path+"/"+escaped))
        return out
    if isinstance(value,list):
        out=[]
        for i,child in enumerate(value):
            out.extend(_flatten(child,path+"/"+str(i)))
        return out
    return [SourceField(path,value)]


def independent_source_fields(raw:str)->list[SourceField]:
    """Use no algorithm or parse output from the PoC source extractor."""
    pri=PRI.match(raw)
    bsd=BSD.match(raw)
    if pri is not None:
        if int(pri.group("priority"))>191:
            raise ValueError("REFERENCE_BAD_PRIORITY")
        body=raw[pri.end():]
        parts=shlex.split(body,posix=True)
        if not parts or not all("=" in item for item in parts):
            raise ValueError("REFERENCE_UNSUPPORTED_KV")
        values={}
        for part in parts:
            key,value=part.split("=",1)
            if key in values:raise ValueError("REFERENCE_DUPLICATE_KV")
            values[key]=value
        return _flatten(values)
    if bsd is not None:
        body=raw[bsd.end():]
        cells=next(csv.reader([body],strict=True))
        return _flatten({f"column_{i}":cell for i,cell in enumerate(cells)})
    value=json.loads(raw)
    if not isinstance(value,dict):
        raise ValueError("REFERENCE_JSON_NOT_OBJECT")
    return _flatten(value)


def evaluate()->dict[str,Any]:
    ref_all=[]
    observed_all=[]
    families=[]
    for case in entries():
        raws,_external_semantic_expected=load_case(case)
        ref=[]
        observed=[]
        for raw in raws:
            parsed=parse_source(raw)
            assert_source_accounting(parsed)
            original_sha=hashlib.sha256(raw.encode("utf8")).hexdigest()
            gold_fields=independent_source_fields(raw)
            ref.append(SourceRecord(
                original_sha,tuple(gold_fields),"SOURCE_PARSED",
                len(raw.encode("utf8")),0,
            ))
            seen=_flatten(parsed.vendor_fields)
            observed.append(SourceRecord(
                original_sha,tuple(seen),parsed.status,
                parsed.source_bytes,parsed.residual_bytes,
            ))
        summary=score_source_fields(ref,observed)
        families.append({
            "fixture":case["id"],
            "records":summary["raw_records_accounted"],
            "gold_vendor_source_fields":summary["gold_source_field_occurrences"],
            "parsed_vendor_source_fields":summary["observed_source_field_occurrences"],
            "exact_field_metrics":summary["exact_source_field"],
            "partial_records":summary["partial_records"],
        })
        ref_all.extend(ref)
        observed_all.extend(observed)
    overall=score_source_fields(ref_all,observed_all)
    result={
        "contract":"parser-studio.poc.pinned-source-field-gold-v0.1",
        "reference":["python json.loads","python csv.reader","python shlex.split"],
        "gold_method":"independent structural source decoders on pinned raw, not ECS expected JSON",
        "total_records":overall["raw_records_accounted"],
        "reference_source_field_occurrences":overall["gold_source_field_occurrences"],
        "extracted_source_field_occurrences":overall["observed_source_field_occurrences"],
        "exact_source_field_metrics":overall["exact_source_field"],
        "fully_parsed_records":overall["fully_parsed_records"],
        "partial_records":overall["partial_records"],
        "raw_only_records":overall["raw_only_records"],
        "unparsed_bytes":overall["unparsed_bytes"],
        "families":families,
        "limitations":[
            "This dataset is the same eight pinned source files used to construct manual profiles, not a new-vendor holdout.",
            "Independent stdlib reference validates original syntactic keys/positions and values, NOT correct ECS/Stellar meaning.",
            "Only JSON, positional CSV and quoted KV variants in these input fixtures are reference-qualified.",
            "Original licensed source and expected JSON files are kept ignored and are not redistributed.",
        ],
        "semantic_normalization_attempted":False,
        "native_verified":False,
        "target_verified":False,
    }
    return result


if __name__=="__main__":
    result=evaluate()
    file=CACHE/"exact_source_fields_result.json"
    file.write_text(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=True)+"\n")
    print("INDEPENDENT SOURCE FIELD GOLD",result["total_records"],
          "fields",result["reference_source_field_occurrences"],
          "scores",result["exact_source_field_metrics"],
          "unparsed_bytes",result["unparsed_bytes"])
    for f in result["families"]:
        print(f["fixture"],"records",f["records"],
              "source_fields",f["gold_vendor_source_fields"],
              "score",f["exact_field_metrics"])
