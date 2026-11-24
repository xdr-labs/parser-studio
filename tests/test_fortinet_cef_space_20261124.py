"""FortiGate CEF with one space after the colon ("CEF: 0|") in the Python Multi-Pass readers (shared CEF grammar)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "multipass"))

from structured_source import decode_cef_or_leef
from security_cef import parse_security_cef
from source_parse import SourceEvent
from generic_structural_poc import parse_generic_structural

BODY = ('CEF: 0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD3915800610 '
        'cat=traffic:forward src=10.1.100.11 spt=54190 dst=52.53.140.235 dpt=443 proto=6 act=close')


class FortinetCefSpace(unittest.TestCase):
    def test_reads_the_header_and_the_extension(self):
        read = decode_cef_or_leef(BODY)
        self.assertEqual(read.issues, [])
        self.assertEqual(read.fields['cef_header']['version'], '0')
        self.assertEqual(read.fields['cef_header']['vendor'], 'Fortinet')
        self.assertEqual(read.fields['cef_header']['severity'], '3')
        self.assertEqual(read.fields['cef_extension']['deviceExternalId'], 'FGT5HD3915800610')
        same = decode_cef_or_leef(BODY.replace('CEF: 0|', 'CEF:0|'))
        self.assertEqual(same.fields, read.fields)

    def test_security_reader_accepts_the_form(self):
        result = parse_security_cef(BODY, base_parser=lambda raw: SourceEvent(raw))
        self.assertEqual(result.syntax, 'CEF_STANDARD')
        self.assertEqual(result.issues, [])

    def test_other_spacing_is_not_cef(self):
        for line in ('CEF:  0|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1',
                     'CEF:\t0|Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1',
                     'CEF: 0 |Fortinet|Fortigate|v6.0.3|00013|n|3|src=10.1.1.1'):
            self.assertNotEqual(decode_cef_or_leef(line).issues, [], line)

    def test_generic_structural_declines_a_malformed_claim_in_an_rfc5424_message(self):
        # Final independent audit F-4: browser and generated Ruby decline these; Python read them as a parsed MSG.
        head = '<189>1 2026-11-24T00:00:00Z FGT-A-LOG app - - - '
        for body in ('CEF :0|A|B|1|2|n|3|src=1.1.1.1', 'CEF\t:0|A|B|1|2|n|3|src=1.1.1.1', 'CEF:  0|A|B|1|2|n|3|src=1.1.1.1',
                     'LEEF :1.0|A|B|1|2|src=1.1.1.1'):
            self.assertNotEqual(parse_generic_structural(head + body).status, 'SOURCE_PARSED', body)
        self.assertEqual(parse_generic_structural(head + 'CEF: 0|A|B|1|2|n|3|src=1.1.1.1').status, 'SOURCE_PARSED')
        self.assertEqual(parse_generic_structural(head + 'CEF:0|A|B|1|2|n|3|src=1.1.1.1').status, 'SOURCE_PARSED')


if __name__ == '__main__':
    unittest.main()
