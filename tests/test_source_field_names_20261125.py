"""G-5 in the Python Multi-Pass preview: field names the JavaScript object model reserves (`__proto__`, `constructor`,
`prototype`) are read and kept under the same reversible names as the browser and the generated Ruby
(src/grammar/sourceFieldNames20261125.test.ts) instead of declining the event. SYNTHETIC lines."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from multipass_preview_api import preview
from source_field_names import SOURCE_NAME_PREFIX, original_field_name, source_field_name

WANT = {'__proto__': 'p1', 'constructor': 'c1', 'prototype': 'r1', SOURCE_NAME_PREFIX + '__proto__': 'x1'}


def leaves(value, out):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                leaves(item, out)
            else:
                out.append((key, item))
    elif isinstance(value, list):
        for item in value:
            leaves(item, out)
    return out


class SourceFieldNames(unittest.TestCase):
    def test_round_trip_and_injective(self):
        names = ['__proto__', 'constructor', 'prototype', 'toString', 'src', 'a.b', '', SOURCE_NAME_PREFIX,
                 SOURCE_NAME_PREFIX + '__proto__', 'parserstudio_key']
        encoded = [source_field_name(name) for name in names]
        self.assertEqual(len(set(encoded)), len(names))
        self.assertEqual([original_field_name(name) for name in encoded], names)

    def test_reserved_names_are_read_and_kept(self):
        lines = {
            'KV': 'src_ip=10.0.0.1 __proto__=p1 constructor=c1 prototype=r1 parserstudio_key___proto__=x1',
            'CEF': 'CEF:0|A|B|1|2|n|3|src=10.0.0.1 __proto__=p1 constructor=c1 prototype=r1 parserstudio_key___proto__=x1',
            'LEEF': 'LEEF:1.0|A|B|1|2|src=10.0.0.1\t__proto__=p1\tconstructor=c1\tprototype=r1\tparserstudio_key___proto__=x1',
            'JSON': '{"src_ip":"10.0.0.1","__proto__":"p1","constructor":"c1","prototype":"r1","parserstudio_key___proto__":"x1"}',
        }
        for label, line in lines.items():
            result = preview(line)
            self.assertEqual(result['status'], 'SOURCE_PARSED', label)
            kept = {original_field_name(key): value for key, value in leaves(result['fields'], [])
                    if value in WANT.values()}
            self.assertEqual(kept, WANT, label)

    def test_duplicates_stay_duplicates(self):
        self.assertNotEqual(preview('{"__proto__":"p1","__proto__":"p2"}')['status'], 'SOURCE_PARSED')


if __name__ == '__main__':
    unittest.main()
