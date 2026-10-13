"""Primary KPI: field extraction and source data preservation, NOT ECS F1.

All records must survive. True extraction success requires parsed values and
NO residual bytes / syntax diagnostics; raw-only preservation does not pass.
Output contains counts only, never vendor field names or source data.
"""
from __future__ import annotations

from collections import Counter
import csv
import json
import shlex
from pathlib import Path
from typing import Any

from corpus import entries,load_case
from source_parse import SourceEvent, assert_source_accounting,parse_source

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"


def _independent_value_check(raw:str,event:SourceEvent)->bool|None:
    """Different stdlib reference decoder for matched, bounded families.

    This is an agreement check, not a comprehensive semantic oracle.
    For escaped vendor KV, the original byte spans and duplicate-key tests
    are the evidence; no independent universal KV spec is assumed.
    """
    try:
        if event.syntax in ("KV","SYSLOG_PRI_KV","SYSLOG_BSD_KV"):
            from engine import BSD,PRI
            offset=0
            if event.syntax=="SYSLOG_PRI_KV":
                match=PRI.match(raw)
                if match is None:return False
                offset=match.end()
            elif event.syntax=="SYSLOG_BSD_KV":
                match=BSD.match(raw)
                if match is None:return False
                offset=match.end()
            tokens=shlex.split(raw[offset:],posix=True)
            if not all("=" in token for token in tokens):
                return False
            entries=[token.split("=",1) for token in tokens]
            if len({key for key,_value in entries})!=len(entries):
                return False
            return dict(entries)==event.vendor_fields and (
                len(entries)==event.primitive_fields)
        if event.syntax=="JSON":
            obj=json.loads(raw)
            if isinstance(obj,dict):
                return obj==event.vendor_fields
            if isinstance(obj,list):
                return {"$array":obj}==event.vendor_fields
        if event.syntax in ("SYSLOG_BSD_CSV","CSV_UNLABELED"):
            if event.syntax=="SYSLOG_BSD_CSV":
                from engine import BSD
                m=BSD.match(raw)
                assert m is not None
                body=raw[m.end():]
            else:
                body=raw
            columns=next(csv.reader([body],strict=True))
            return columns==[event.vendor_fields[f"column_{i}"]
                             for i in range(len(columns))] and (
                                 len(columns)==event.primitive_fields)
    except (csv.Error,ValueError,IndexError,AssertionError):
        return False
    return None


def evaluate_source()->dict[str,Any]:
    total=Counter()
    matrix=[]
    for case in entries():
        raw,_expected=load_case(case)
        stats=Counter()
        kinds=Counter()
        errors=Counter()
        for line in raw:
            e=parse_source(line)
            assert_source_accounting(e)
            assert e.raw==line
            stats["events"]+=1
            stats["raw_bytes"]+=e.source_bytes
            stats["residual_bytes"]+=e.residual_bytes
            stats["syntax_covered_bytes"]+=e.source_bytes-e.residual_bytes
            stats["source_field_values"]+=e.primitive_fields
            stats["source_value_spans"]+=len(e.value_spans)
            stats["with_at_least_one_source_field"]+=bool(e.vendor_fields)
            stats["without_any_source_field"]+=not bool(e.vendor_fields)
            stats["source_parsed_events"]+=e.status=="SOURCE_PARSED"
            stats["partial_events"]+=e.status=="PARTIAL"
            stats["raw_only_events"]+=e.status=="RAW_ONLY"
            stats["structured_empty_events"]+=e.status=="STRUCTURED_EMPTY"
            kinds[e.syntax]+=1
            for issue in e.issues:
                errors[issue.split(":",1)[0]]+=1
            alternate=_independent_value_check(line,e)
            if alternate is not None:
                stats["reference_check_events"]+=1
                stats["reference_agreement_events"]+=alternate
            # All value ranges live inside original source bytes and every
            # event remains, even if no source fields could be extracted.
        total.update(stats)
        matrix.append({
            "id":case["id"],"records":len(raw),
            "events_with_fields":stats["with_at_least_one_source_field"],
            "fully_structured_events":stats["source_parsed_events"],
            "partial_events":stats["partial_events"],
            "raw_only_events":stats["raw_only_events"],
            "source_fields":stats["source_field_values"],
            "source_value_spans":stats["source_value_spans"],
            "unparsed_bytes":stats["residual_bytes"],
            "source_bytes":stats["raw_bytes"],
            "reference_agree":stats["reference_agreement_events"],
            "reference_checked":stats["reference_check_events"],
            "syntaxes":dict(sorted(kinds.items())),
            "issues":dict(sorted(errors.items())),
        })
    assert total["events"]==256
    parsed=total["source_parsed_events"]
    return {
        "contract":"parser-studio.poc.extraction-first-result.v0.1",
        "stage":"SOURCE_PARSE_ONLY_NO_DICTIONARY_NO_NORMALIZATION",
        "raw_records_preserved":total["events"],
        "records_with_extracted_fields":total["with_at_least_one_source_field"],
        "fully_structured_parsed_events":parsed,
        "partial_events":total["partial_events"],
        "raw_only_events":total["raw_only_events"],
        "structured_empty_events":total["structured_empty_events"],
        "event_structural_success_rate":round(parsed/total["events"],4),
        "event_field_presence_rate":round(
            total["with_at_least_one_source_field"]/total["events"],4),
        "source_field_values":total["source_field_values"],
        "source_value_spans":total["source_value_spans"],
        "source_bytes":total["raw_bytes"],
        "syntax_parsed_bytes":total["syntax_covered_bytes"],
        "unparsed_bytes":total["residual_bytes"],
        "syntax_coverage_rate":round(
            total["syntax_covered_bytes"]/total["raw_bytes"],4),
        "independent_decoder_agreement_events":total["reference_agreement_events"],
        "independent_decoder_checked_events":total["reference_check_events"],
        "reference_algorithms":["stdlib json.loads","stdlib csv.reader","stdlib shlex.split"],
        "fixtures":matrix,
        "all_original_records_preserved":True,
        "normalization_attempted":False,
        "native_verified":False,
        "stellar_target_verified":False,
        "limitations":[
            "Structural success is NOT independently gold-labeled source-field precision/recall.",
            "Retaining original raw bytes is not equivalent to parsing them.",
            "Reference cross-decoder compares JSON, CSV and KV via independent stdlib primitives; it is not separately labeled source-field gold.",
            "Licensed upstream raw/gold fixtures remain ignored under .cache/.",
        ],
    }


if __name__=="__main__":
    output=evaluate_source()
    path=CACHE/"source_parse_result.json"
    path.write_text(json.dumps(output,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
    print("SOURCE PARSE",output["raw_records_preserved"],
          "WITH FIELDS",output["records_with_extracted_fields"],
          "FULLY STRUCTURED",output["fully_structured_parsed_events"],
          "PARTIAL",output["partial_events"],
          "RAW ONLY",output["raw_only_events"],
          "FIELD VALUES",output["source_field_values"],
          "SYNTAX COVERAGE",output["syntax_coverage_rate"],
          "REF AGREEMENT",output["independent_decoder_agreement_events"],
          "/",output["independent_decoder_checked_events"])
    for row in output["fixtures"]:
        print(row["id"],"records",row["records"],
              "full",row["fully_structured_events"],"partial",row["partial_events"],
              "raw",row["raw_only_events"],"fields",row["source_fields"],
              "issue counts",row["issues"])
    print("AGGREGATE ONLY",path)
