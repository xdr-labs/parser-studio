import json
import unittest

from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from visible_redaction import assess_visible_redaction,summarize_visible_redaction


class VisibleRedactionRecognitionTests(unittest.TestCase):
    def assert_marker(self,raw,path,token,marker):
        event=parse_security_multipass(raw)
        before=json.dumps(event.vendor_fields,sort_keys=True,ensure_ascii=False)
        result=assess_visible_redaction(event)
        self.assertEqual("EXPLICIT_VISIBLE_MASKS",result.assessment)
        found=[x for x in result.occurrences if x.source_path==path]
        self.assertEqual(1,len(found))
        item=found[0]
        self.assertEqual(marker,item.marker_class)
        self.assertEqual(token,raw.encode("utf8")[item.start_byte:item.end_byte].decode("utf8"))
        self.assertEqual(before,json.dumps(event.vendor_fields,sort_keys=True,ensure_ascii=False))
        self.assertEqual(raw,event.raw)
        assert_source_accounting(event)
        self.assertFalse(event.normalization_attempted)
        return event,result

    def test_json_and_cee_markers_are_recognized_without_reconstruction(self):
        raw='{"src":"REDACTED","payload":"***","note":"visible","mixed":"redacted-user"}'
        event,result=self.assert_marker(raw,"src","REDACTED","REDACTED_KEYWORD")
        by_path={x.source_path:x.marker_class for x in result.occurrences}
        self.assertEqual("ASTERISK_RUN",by_path["payload"])
        self.assertNotIn("mixed",by_path)
        self.assertEqual("***",event.vendor_fields["payload"])
        self.assertEqual("redacted-user",event.vendor_fields["mixed"])

        cee='@cee: {"src_ip":"[REDACTED]","user":"<MASKED>","n":7}'
        _,result= self.assert_marker(cee,"src_ip","[REDACTED]","REDACTED_KEYWORD")
        self.assertEqual(
            {"src_ip":"REDACTED_KEYWORD","user":"MASKED_KEYWORD"},
            {x.source_path:x.marker_class for x in result.occurrences},
        )

    def test_kv_and_cef_repeated_markers_keep_exact_occurrence_spans(self):
        kv='srcip=MASKED action=allow secret=********'
        _,result=self.assert_marker(kv,"srcip","MASKED","MASKED_KEYWORD")
        self.assertEqual(2,result.explicit_mask_occurrences)

        cef='CEF:0|Synthetic|FW|1|42|Blocked|8|cs1=*** cs1=REDACTED src=192.0.2.1'
        event=parse_security_multipass(cef)
        result=assess_visible_redaction(event)
        masks=[x for x in result.occurrences if x.source_path=="cef_extension.cs1"]
        self.assertEqual([0,1],[x.occurrence for x in masks])
        self.assertEqual(["***","REDACTED"],[
            cef.encode("utf8")[x.start_byte:x.end_byte].decode("utf8") for x in masks
        ])
        self.assertEqual(["***","REDACTED"],event.vendor_fields["cef_extension"]["cs1"])

    def test_absence_of_literal_marker_is_not_called_unmasked(self):
        raw='srcip=192.0.2.1 action=allow note=xxxxx'
        event=parse_security_multipass(raw)
        result=assess_visible_redaction(event)
        self.assertEqual("NOT_ASSESSED_NO_LITERAL_MARKER",result.assessment)
        self.assertEqual(0,result.explicit_mask_occurrences)
        self.assertGreater(result.unassessed_visible_occurrences,0)
        report=result.report()
        self.assertFalse(report["hidden_value_reconstruction"])
        self.assertTrue(report["source_extraction_preserved"])

    def test_raw_only_source_is_excluded_not_silently_scored(self):
        raw='plain sentence REDACTED but no supported source structure'
        event=parse_security_multipass(raw)
        result=assess_visible_redaction(event)
        self.assertEqual("EXCLUDED_NO_SOURCE_OCCURRENCES",result.assessment)
        self.assertEqual(0,result.source_occurrences)
        self.assertEqual((),result.occurrences)
        self.assertEqual(raw,event.raw)
        assert_source_accounting(event)

    def test_summary_separates_masked_unassessed_and_excluded_denominators(self):
        raws=[
            '{"src":"REDACTED","action":"deny"}',
            'srcip=MASKED action=allow',
            'CEF:0|S|P|1|1|n|5|src=192.0.2.1 cs1=***',
            '{"src":"192.0.2.1","action":"allow"}',
            'srcip=198.51.100.1 action=deny',
            'unknown prose one',
            'unknown prose two',
        ]
        result=summarize_visible_redaction(parse_security_multipass(x) for x in raws)
        self.assertEqual(7,result["events"])
        self.assertEqual(3,result["masked_events"])
        self.assertEqual(2,result["unassessed_events"])
        self.assertEqual(2,result["excluded_events"])
        self.assertEqual(3,result["explicit_mask_occurrences"])
        self.assertEqual(0,result["hidden_values_reconstructed"])
        self.assertFalse(result["absence_of_marker_proves_unmasked"])
        self.assertEqual(result["events"],
                         result["masked_events"]+result["unassessed_events"]+result["excluded_events"])


if __name__=="__main__":
    unittest.main()
