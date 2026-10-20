"""Independent RFC 3164/BSD TAG and CONTENT source fidelity checks.

Test-only synthetic messages; no manufacturer semantic or target-native oracle.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime/multipass"))
from multipass_preview_api import preview,preview_batch
from source_parse import parse_source,assert_source_accounting
from security_framing import parse_security_batch,assert_batch_accounting

PRI = "<134>Oct 19 08:12:00 edge-fw firewall: "
BARE = "Oct 19 08:12:00 edge-fw auth: "

class FreeFormSyslogContent(unittest.TestCase):
    def checked(self,raw,msg,syntax):
        direct=parse_source(raw)
        assert_source_accounting(direct)
        self.assertEqual(direct.status,"SOURCE_PARSED")
        result=preview(raw)
        self.assertEqual(result["status"],"SOURCE_PARSED")
        self.assertEqual(result["syntax"],syntax)
        self.assertEqual(result["fields"]["body"],{"message":msg})
        self.assertEqual(result["issues"],[])
        self.assertEqual(result["residuals"],[])
        self.assertFalse(result["nativeVerified"])
        self.assertFalse(result["targetVerified"])
        self.assertNotIn("year",result["fields"]["syslog"])
        self.assertNotIn("timezone",result["fields"]["syslog"])
        self.assertNotIn("timestamp",result["fields"]["syslog"])
        spans=[s for s in result["spans"] if s["path"]=="body.message"]
        self.assertEqual(len(spans),1)
        data=raw.encode("utf8")
        s=spans[0]
        self.assertEqual(data[s["startByte"]:s["endByte"]],msg.encode("utf8"))
        self.assertEqual(s["startByte"],len(raw[:-len(msg)].encode("utf8")))
        self.assertEqual(s["endByte"],len(data))
        return result

    def test_pri_bsd_tag_free_text(self):
        self.checked(PRI+"Access blocked by a reviewed policy",
                     "Access blocked by a reviewed policy",
                     "SYSLOG_RFC3164+RFC3164_CONTENT")

    def test_unprefixed_bsd_tag_free_text(self):
        self.checked(BARE+"User denied access by policy",
                     "User denied access by policy",
                     "BSD_SYSLOG+BSD_CONTENT")

    def test_multilingual_utf8_offsets(self):
        self.checked(PRI+"사용자 김민수 접근 차단 🔐",
                     "사용자 김민수 접근 차단 🔐",
                     "SYSLOG_RFC3164+RFC3164_CONTENT")

    def test_bracketed_non_json_prose(self):
        self.checked(PRI+"[Blocked] policy rejected connection",
                     "[Blocked] policy rejected connection",
                     "SYSLOG_RFC3164+RFC3164_CONTENT")

    def test_delimiter_spaces_consumed_as_syntax_and_content_tail_preserved(self):
        # The strict BSD header consumes spacing immediately after TAG: as
        # syntax. The remaining CONTENT has its exact original byte span.
        raw=PRI+"  Blocked access  "
        result=self.checked(raw,"Blocked access  ",
                            "SYSLOG_RFC3164+RFC3164_CONTENT")
        self.assertEqual(result["sourceBytes"],len(raw.encode("utf8")))
        self.assertEqual(result["residuals"],[])

    def test_ip_atoms_must_not_be_lost_to_one_catchall_message(self):
        raw=(PRI+"session denied 192.0.2.12/52333 to "
             "198.51.100.9/80 after policy review")
        result=preview(raw)
        self.assertEqual(result["status"],"PARTIAL")
        self.assertNotIn("message",result["fields"].get("body",{}))
        self.assertIn("192.0.2.12/52333",
                      result["fields"]["generic_atoms"]["network"])
        self.assertIn("198.51.100.9/80",
                      result["fields"]["generic_atoms"]["network"])

    def test_labeled_source_evidence_not_replaced_by_message(self):
        raw=PRI+"[Action: DENY] [Reason: blocked]"
        result=preview(raw)
        self.assertNotEqual(result["status"],"SOURCE_PARSED")
        self.assertNotIn("message",result["fields"].get("body",{}))
        self.assertTrue(result["spans"])
        self.assertIn("DENY",str(result["fields"]))

    def test_structured_kv_preserved(self):
        p=preview(PRI+"action=deny src=192.0.2.9")
        self.assertEqual(p["status"],"SOURCE_PARSED")
        self.assertEqual(p["syntax"],"SYSLOG_RFC3164+KV")
        self.assertEqual(p["fields"]["body"]["src"],"192.0.2.9")
        self.assertNotIn("message",p["fields"]["body"])

    def test_cef_not_collapsed_to_message(self):
        p=preview(PRI+"CEF:0|Example|Security|1|42|Denied|5|src=192.0.2.9 act=deny")
        self.assertEqual(p["status"],"SOURCE_PARSED")
        self.assertNotIn("message",p["fields"].get("body",{}))

    def test_invalid_quoted_kv_remains_review(self):
        p=preview(PRI+'action="unfinished src=192.0.2.9')
        self.assertNotEqual(p["status"],"SOURCE_PARSED")
        self.assertNotIn("message",p["fields"].get("body",{}))

    def test_incomplete_json_array_remains_review(self):
        p=preview(PRI+'[{"action":"deny"')
        self.assertNotEqual(p["status"],"SOURCE_PARSED")
        self.assertNotIn("message",p["fields"].get("body",{}))

    def test_colon_delimited_non_json_array_like_needs_review(self):
        # A bracket-shaped pseudo-JSON candidate must not be made
        # a verified native/source grammar merely because it has a prefix.
        p=preview(PRI+"[1:2024218:3] classification alert")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_invalid_calendar_header_never_complete(self):
        p=preview("<134>Oct 35 08:12:00 edge-fw firewall: policy deny")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_bad_pri_not_complete(self):
        p=preview(PRI.replace("<134>","<999>")+"Access blocked by policy")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_multiline_never_silent_single_complete(self):
        p=preview(PRI+"Blocked\nunframed next line")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_tab_control_in_standard_printable_content_not_promoted(self):
        p=preview(PRI+"User\tdenied")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_no_unframed_plain_prose_promotion(self):
        p=preview("User denied access after policy review")
        self.assertNotEqual(p["status"],"SOURCE_PARSED")

    def test_two_original_bsd_events_with_exact_byte_ledger(self):
        raw=PRI+"Access denied\n"+BARE+"로그 확인"
        batch=preview_batch(raw)
        self.assertEqual(batch["eventCount"],2)
        self.assertEqual([e["preview"]["status"] for e in batch["events"]],
                         ["SOURCE_PARSED","SOURCE_PARSED"])
        self.assertEqual(batch["sourceBytes"],len(raw.encode("utf8")))
        assert_batch_accounting(parse_security_batch(raw))
        for event,expected in zip(batch["events"],["Access denied","로그 확인"]):
            p=event["preview"]
            self.assertEqual(p["fields"]["body"]["message"],expected)
            self.assertEqual(p["sourceBytes"],event["endByte"]-event["startByte"])
            self.assertFalse(p["targetVerified"])

if __name__=="__main__":
    unittest.main()
