"""Independent CC0 Log Zoo samples are pinned and evaluated offline only.

No upstream bytes or customer logs are redistributed. The CC0 repository
revision is checked exactly; each file's SHA256 is checked before parsing.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import subprocess
import unittest

from source_parse import parse_source,assert_source_accounting

CACHE=Path(__file__).resolve().parent/".cache"/"log-zoo"
REPO="https://github.com/sva-s1/log-zoo"
COMMIT="f61b0d7f345f47349a376629bfc3165752b77ade"
CASES={
    "cef/xypro_nonstop_object_access.log":"60d4baabe674b6002124411f64cc6a7a53e4ec870ba51ecc69354f1dbc8ce92b",
    "fortinet/event.type/security-rating/fortigate.log":"166173ace1190701dbf2b25481de058293e5009c64eaa3e95842e027aa5f821d",
    "fortinet/event.type/system/fortigate.log":"f94916021646a329a483713b972efecf2154f5da4c389123be91f06eba0ac9de",
    "fortinet/event.type/traffic/fortigate.log":"9f639643d2f646db6847ac552e71ac4ea55cbb6df4305df28efadc4f4907ee09",
}


def load()->dict[str,list[str]]:
    head=subprocess.run(
        ["git","-C",str(CACHE),"rev-parse","HEAD"],
        capture_output=True,text=True,check=True,
    ).stdout.strip()
    if head!=COMMIT:
        raise ValueError("PUBLIC_NEW_SOURCE_COMMIT_MISMATCH")
    out={}
    for name,pin in CASES.items():
        content=(CACHE/name).read_bytes()
        if hashlib.sha256(content).hexdigest()!=pin:
            raise ValueError("PUBLIC_NEW_SOURCE_SHA256_MISMATCH")
        if len(content)>1048576:
            raise ValueError("PUBLIC_NEW_SOURCE_TOO_LARGE")
        out[name]=[
            x for x in content.decode("utf8","strict").splitlines()
            if x.strip()
        ]
    return out


def evaluate()->dict:
    corpus=load()
    stats=Counter()
    per_file=[]
    for name,rows in corpus.items():
        group=Counter()
        for item in rows:
            parsed=parse_source(item)
            assert_source_accounting(parsed)
            assert parsed.raw==item
            assert not parsed.normalization_attempted
            group["records"]+=1
            group["source_parsed"]+=parsed.status=="SOURCE_PARSED"
            group["partial"]+=parsed.status=="PARTIAL"
            group["raw_only"]+=parsed.status=="RAW_ONLY"
            group["fields"]+=parsed.primitive_fields
            group["unparsed_bytes"]+=parsed.residual_bytes
            group["source_bytes"]+=parsed.source_bytes
        stats.update(group)
        per_file.append({"id":name.split("/")[0],
                         "records":group["records"],
                         "source_parsed":group["source_parsed"],
                         "fields":group["fields"]})
    return {"contract":"parser-studio.poc.external-cc0-source.v0.1",
            "source_repository":REPO,"pinned_commit":COMMIT,
            "license":"CC0 1.0 (repository claim; raw retained local only)",
            "aggregate":dict(stats),"by_family":per_file,
            "semantics_verified":False,
            "dictionary_mapping_attempted":False,
            "native_target_verified":False}


class IndependentSourceTests(unittest.TestCase):
    @unittest.skipUnless((CACHE/".git").is_dir(),
                         "External CC0 sample is only in ignored local cache")
    def test_pinned_independent_log_zoo_corpus_is_structured_without_dictionary(self):
        summary=evaluate()
        stats=summary["aggregate"]
        self.assertEqual(4,stats["records"])
        self.assertEqual(4,stats["source_parsed"])
        self.assertEqual(0,stats["raw_only"])
        self.assertEqual(0,stats["partial"])
        self.assertEqual(0,stats["unparsed_bytes"])
        self.assertGreater(stats["fields"],40)


if __name__=="__main__":
    unittest.main()
