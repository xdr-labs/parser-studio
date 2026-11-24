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
from multipass_preview_api import preview

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


LEEF = ('LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.10^dst=172.50.123.1^sev=5^cat=anomaly^srcPort=81'
        '^dstPort=21^usrName=joe.black')


class LeefHeaderSpacing(unittest.TestCase):
    """IBM QRadar LEEF guide: the header is "LEEF:Version|", with no space after the colon (audit A-6). The browser
    journey declines these lines too (src/grammar/cefLeefHeaderForms20261124.test.ts)."""

    def test_a_space_after_the_colon_is_not_leef(self):
        spaced = LEEF.replace('LEEF:', 'LEEF: ', 1)
        self.assertNotEqual(decode_cef_or_leef(spaced).issues, [])
        for line in (spaced, '<111>' + spaced, '<111>Apr 19 10:29:53 3.3.3.3 ' + spaced):
            self.assertNotEqual(preview(line)['status'], 'SOURCE_PARSED', line)

    def test_the_documented_form_is_leef(self):
        self.assertEqual(decode_cef_or_leef(LEEF).issues, [])
        for line in (LEEF, '<111>Apr 19 10:29:53 3.3.3.3 ' + LEEF):
            self.assertEqual(preview(line)['status'], 'SOURCE_PARSED', line)


class PreviewDeclinesMalformedClaimInsideSyslog(unittest.TestCase):
    """Final re-audit H-3: the Multi-Pass preview endpoint (parse_security_multipass) read a malformed CEF/LEEF claim
    inside an RFC 5424 message, or after an RFC 3164 header, as a parsed free-form message; the browser and the
    generated Ruby decline it."""

    def test_malformed_claims_are_not_parsed(self):
        heads = ('<189>1 2026-11-24T00:00:00Z FGT-A-LOG app - - - ', '<189>Dec 27 11:07:55 FGT-A-LOG ')
        for head in heads:
            for body in ('CEF :0|A|B|1|2|n|3|src=1.1.1.1', 'CEF\t:0|A|B|1|2|n|3|src=1.1.1.1',
                         'CEF:  0|A|B|1|2|n|3|src=1.1.1.1', 'LEEF :1.0|A|B|1|2|src=1.1.1.1'):
                self.assertNotEqual(preview(head + body)['status'], 'SOURCE_PARSED', head + body)

    def test_valid_claims_stay_parsed(self):
        for head in ('<189>1 2026-11-24T00:00:00Z FGT-A-LOG app - - - ', '<189>Dec 27 11:07:55 FGT-A-LOG '):
            for body in ('CEF: 0|A|B|1|2|n|3|src=1.1.1.1', 'CEF:0|A|B|1|2|n|3|src=1.1.1.1'):
                self.assertEqual(preview(head + body)['status'], 'SOURCE_PARSED', head + body)

    def test_free_text_messages_stay_parsed(self):
        self.assertEqual(preview('<189>1 2026-11-24T00:00:00Z FGT-A-LOG app - - - service restarted')['status'],
                         'SOURCE_PARSED')


if __name__ == '__main__':
    unittest.main()
