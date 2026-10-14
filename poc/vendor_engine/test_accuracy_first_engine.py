import dataclasses
import unittest

from benchmark_multipass_security_gate import evaluate
from multipass_adjudicator import parse_security_multipass
from security_document import parse_security_document
from security_framing import parse_security_batch
from security_source import parse_security_source


class AccuracyFirstEngineDecisionTests(unittest.TestCase):
    def test_mp8_selects_multipass_while_preserving_base_engine(self):
        result=evaluate()
        self.assertEqual('SELECT_AS_AUTO_PARSER_SOURCE_CANDIDATE',result['decision'])
        self.assertEqual('multipass_adjudicator.parse_security_multipass',result['selected_engine'])
        self.assertEqual('security_source.parse_security_source',result['base_engine_preserved'])

        raw='CEF:0|V|IPS|1|42|Alert|5|msg="quoted value"   act=deny'
        selected=parse_security_multipass(raw)
        self.assertNotEqual(parse_security_source(raw).vendor_fields,selected.vendor_fields)
        self.assertEqual('"quoted value"  ',selected.vendor_fields['cef_extension']['msg'])

    def test_selected_parser_composes_with_framing_and_document_state(self):
        raw='{"action":"BLOCK"}\nLEEF:2.0|V|IPS|1|42|x7C|src=192.0.2.1|act=deny'
        batch=parse_security_batch(raw,parser=parse_security_multipass)
        self.assertEqual(2,len(batch.frames))
        self.assertEqual('BLOCK',batch.frames[0].event.vendor_fields['action'])
        self.assertEqual('deny',batch.frames[1].event.vendor_fields['leef_extension']['act'])

        rows=[
            r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring',
            'u1\tallow','{"action":"BLOCK"}','#close\tnow',
            'LEEF:2.0|V|IPS|1|42|x7C|src=192.0.2.1|act=deny',
        ]
        document=parse_security_document(rows,base_parser=parse_security_multipass)
        events=dict(document.events)
        self.assertEqual({'uid':'u1','action':'allow'},events[3].vendor_fields)
        self.assertEqual('BLOCK',events[4].vendor_fields['action'])
        self.assertEqual('deny',events[6].vendor_fields['leef_extension']['act'])
        self.assertEqual(list(range(len(rows))),sorted(document.metadata_indices+[i for i,_ in document.events]))

    def test_source_selection_does_not_attempt_dictionary_or_hidden_mask_recovery(self):
        event=parse_security_multipass('{"unknown.native":"visible","masked":"***"}')
        self.assertFalse(event.normalization_attempted)
        self.assertEqual('visible',event.vendor_fields['unknown.native'])
        self.assertEqual('***',event.vendor_fields['masked'])
        result=evaluate()
        self.assertFalse(result['dictionary_attempted'])
        self.assertFalse(result['masking_optimization'])
        self.assertFalse(result['runtime_is_acceptance_gate'])


if __name__=='__main__':
    unittest.main()
