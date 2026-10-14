"""Value-free coverage evidence for optional Stellar Dictionary normalization.

This benchmark measures only deterministic mapping coverage and source
preservation. It does NOT treat an unmapped field as a source-parser failure,
does NOT score vendor semantic correctness unless the source alias is an
independently standardized CEF key, and never publishes source values.
"""
from __future__ import annotations

from collections import Counter
import hashlib,json
from pathlib import Path

from benchmark_commercial_security import CACHE as SECURITY_CACHE,MANIFEST as SECURITY_MANIFEST
from benchmark_multipass_cef import authored as cef_authored,commercial as cef_commercial
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from stellar_dictionary import (
    DICTIONARY_REVISION,FIELDS,OFFICIAL_DICTIONARY_URL_65,OFFICIAL_DICTIONARY_URL_70,
    CEF_DICTIONARY_URL,normalize_stellar_dictionary,
)

HERE=Path(__file__).resolve().parent

def _measure(rows:list[str])->dict:
    counts=Counter()
    targets=Counter();rules=Counter();issues=Counter()
    for raw in rows:
        event=parse_security_multipass(raw);assert_source_accounting(event)
        before=deepcopy_tree(event.vendor_fields)
        result=normalize_stellar_dictionary(event)
        counts["records"]+=1
        counts["raw_preserved"]+=event.raw==raw
        counts["source_tree_preserved"]+=event.vendor_fields==before==result.source_fields
        counts["source_extraction_normalization_attempted_false"]+=not event.normalization_attempted
        counts["source_occurrences"]+=len(event.value_spans)
        counts["mapped_occurrences"]+=len(result.mappings)
        counts["unmapped_occurrences"]+=len(result.unmapped_occurrences)
        counts["normalized_fields"]+=len(result.normalized_fields)
        for item in result.mappings:
            targets[item.dictionary_field]+=1
            rules["cef_standard_alias" if item.rule_id.startswith("cef:") else "exact_dictionary_name"]+=1
        issues.update(result.issues)
    if counts["mapped_occurrences"]+counts["unmapped_occurrences"]!=counts["source_occurrences"]:
        raise AssertionError("DICTIONARY_BENCHMARK_ACCOUNTING_FAILED")
    return {
        **dict(counts),
        "mapping_targets":dict(sorted(targets.items())),
        "mapping_rule_classes":dict(sorted(rules.items())),
        "issues":dict(sorted(issues.items())),
    }

def deepcopy_tree(value):
    # JSON-compatible source trees only; avoids importing candidate internals.
    import copy
    return copy.deepcopy(value)

def _security_rows()->tuple[list[str],str]:
    manifest_bytes=SECURITY_MANIFEST.read_bytes()
    manifest=json.loads(manifest_bytes)
    rows=[]
    for item in manifest:
        blob=(SECURITY_CACHE/(item["id"]+".raw")).read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item["sha256"]:
            raise ValueError("DICTIONARY_SECURITY_SOURCE_PIN_MISMATCH")
        decoded=blob.decode("utf8","strict").splitlines()
        if len(decoded)!=item["physical_lines"]:
            raise ValueError("DICTIONARY_SECURITY_SOURCE_COUNT_MISMATCH")
        rows.extend(decoded)
    return rows,hashlib.sha256(manifest_bytes).hexdigest()

def evaluate()->dict:
    security_rows,security_manifest_sha=_security_rows()
    cef_commercial_rows,_=cef_commercial()
    authored_rows=cef_authored()
    commercial_cef=[item["raw"] for item in cef_commercial_rows]
    authored_cef=[item["raw"] for item in authored_rows]
    return {
        "contract":"parser-studio.poc.stellar-dictionary-coverage.v0.1",
        "dictionary_revision":DICTIONARY_REVISION,
        "dictionary_field_count":len(FIELDS),
        "source_urls":[OFFICIAL_DICTIONARY_URL_65,OFFICIAL_DICTIONARY_URL_70,CEF_DICTIONARY_URL],
        "measurement":"Value-free mapping coverage and source-occurrence preservation only; not open-world semantic accuracy.",
        "security_commercial":_measure(security_rows),
        "cef_commercial":_measure(commercial_cef),
        "cef_authored":_measure(authored_cef),
        "security_manifest_sha256":security_manifest_sha,
        "unknown_vendor_fields_preserved":True,
        "automatic_generic_alias_inference":False,
        "source_extraction_gate_independent":True,
        "native_verified":False,
        "target_verified":False,
        "raw_redistributed":False,
    }

if __name__=="__main__":
    result=evaluate()
    out=HERE/"stellar-dictionary-summary.json"
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    for name in ("security_commercial","cef_commercial","cef_authored"):
        print(name,result[name])
