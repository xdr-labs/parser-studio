#!/usr/bin/env python3
"""Freeze RFC8259/RFC7464 independent lexical truth before candidate scoring."""
from pathlib import Path
import hashlib
import json

# Explicitly specified valid/error cases. "uncertain" is NOT invalid JSON.
cases = [
 ("JSON-ORDINARY-UTF8", '{"vendor":"Example","event":{"user":"봄","action":"allow"},"value":42}', "review_lexical", [], "Example"),
 ("JSON-VALID-SURROGATE-PAIR", r'{"emoji":"\uD83D\uDE00","number":1.5}', "review_lexical", [], "\U0001F600"),
 ("JSON-DISTINCT-SCOPED-KEYS", '{"left":{"key":"A"},"right":{"key":"B"}}', "review_lexical", [], "A"),
 ("JSON-ARRAY-IN-OBJECT", '{"tags":["a","b"],"enabled":true,"count":3}', "review_lexical", [], "a"),
 ("JSON-DUPLICATE-ROOT", '{"user":"alice","user":"bob"}', "review_uncertain", ["DUPLICATE_MEMBER_SILENT_OVERWRITE"], None),
 ("JSON-DUPLICATE-ESCAPED-NESTED", r'{"event":{"user":"a","\u0075ser":"b"}}', "review_uncertain", ["DUPLICATE_MEMBER_SILENT_OVERWRITE"], None),
 ("JSON-NONFINITE-EXPONENT", '{"score":1e999}', "review_uncertain", ["NONFINITE_NUMBER_OR_LOSS_OF_PRECISION"], None),
 ("JSON-UNSAFE-INTEGER", '{"counter":9007199254740993}', "review_uncertain", ["NONFINITE_NUMBER_OR_LOSS_OF_PRECISION"], None),
 ("JSON-UNSAFE-FRACTION-PRECISION", '{"number":1.1234567890123456789}', "review_uncertain", ["NONFINITE_NUMBER_OR_LOSS_OF_PRECISION"], None),
 ("JSON-UNPAIRED-HIGH-SURROGATE", r'{"name":"\uD800"}', "review_uncertain", ["UNPAIRED_UNICODE_SURROGATE"], None),
 ("JSON-UNPAIRED-LOW-SURROGATE", r'{"name":"\uDE00"}', "review_uncertain", ["UNPAIRED_UNICODE_SURROGATE"], None),
 ("JSON-INVALID-TRAILING-BYTES", '{"name":"alice"}garbage', "abstain", ["INVALID_SOURCE_LEXICAL_GRAMMAR"], None),
 ("JSON-INVALID-ESCAPE", r'{"message":"bad\q"}', "abstain", ["INVALID_SOURCE_LEXICAL_GRAMMAR"], None),
 ("JSON-TRUNCATED-OBJECT", '{"name":"alice"', "abstain", ["INVALID_SOURCE_LEXICAL_GRAMMAR"], None),
]
out=[]
for id,wire,disposition,issues,expected in cases:
    raw=wire.encode('utf8')
    record={"id":id,"wire":wire,"expectedDisposition":disposition,"issues":issues,
            "sourceBytes":len(raw),"sourceSha256":hashlib.sha256(raw).hexdigest()}
    if expected is not None:record["expectedSourceValue"]=expected
    out.append(record)
payload={"standardReferences":["RFC8259 sections 4, 6, 7, 8", "RFC7464 sections 2.2, 2.4"],
  "evidence":"independently authored standards-derived synthetic; not manufacturer/native correctness",
  "cases":out}
raw=(json.dumps(payload,ensure_ascii=False,indent=2)+"\n").encode('utf8')
p=Path('scripts/poc/standardJsonSourceSafety.pinned.json')
p.write_bytes(raw)
print("FROZEN",len(out),"CASES",hashlib.sha256(raw).hexdigest())
