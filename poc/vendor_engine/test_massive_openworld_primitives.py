"""Massive open-world structural primitives discovered after corpus freeze."""
import json
import unittest

from multipass_adjudicator import parse_security_multipass,parse_security_once
from source_parse import assert_source_accounting


class MassiveOpenWorldPrimitiveTests(unittest.TestCase):
    def test_rfc3164_multiple_spaces_before_tag_keeps_json_body(self):
        raw=(
            '<174>May 24 13:09:53 INFO  uvm[0]:  '
            '{"timeStamp":"2023-05-24 13:09:53.477",'
            '"login":"admin","succeeded":true}'
        )
        event=parse_security_multipass(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual('SYSLOG_RFC3164+JSON',event.syntax)
        self.assertEqual('INFO',event.vendor_fields['syslog']['host'])
        self.assertEqual('uvm[0]',event.vendor_fields['syslog']['tag'])
        self.assertTrue(event.vendor_fields['body']['succeeded'])

    def test_pure_comma_kv_supports_quoted_commas_without_semantics(self):
        raw=(
            '<190>date=2023-01-30,time=16:09:15.246,'
            'device_id=abc123,log_id=0400003064,type=virus,'
            'subtype=infected,pri=information,'
            'msg="file is infected, action retained"'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('COMMA_KV',event.syntax)
        self.assertEqual(
            'file is infected, action retained',
            event.vendor_fields['generic']['fields']['msg'],
        )
        span=next(
            item for item in event.value_spans
            if item.path=='generic.kv.msg'
        )
        self.assertEqual(
            'file is infected, action retained',
            raw.encode()[span.start_byte:span.end_byte].decode(),
        )

    def test_prefixed_delimited_kv_supports_comma_and_semicolon_runs(self):
        cases=(
            (
                '_fsservice : TTY=unknown ; PWD=/usr/local/forescout ; '
                'USER=root ; COMMAND=/bin/fstool',
                ';','TTY','unknown',
            ),
            (
                '<166>Mar 17 18:24:37 amp: Info: query starting. '
                "File Name = 'mod-6.exe', MID = 5, "
                'File Size = 1673216 bytes, File Type = application/x-dosexec',
                ',','File Name','mod-6.exe',
            ),
        )
        for raw,delimiter,key,value in cases:
            with self.subTest(delimiter=delimiter):
                event=parse_security_once(raw);assert_source_accounting(event)
                self.assertEqual('SOURCE_PARSED',event.status)
                self.assertIn('DELIMITED_KV',event.syntax)
                self.assertEqual(
                    value,event.vendor_fields['generic']['fields'][key]
                )

    def test_prefixed_delimited_kv_four_field_gate_rejects_weak_lookalikes(self):
        bad=(
            'notice: a=1, b=2, c=3',
            'notice: a=1; b=2; c=3',
            'url=https://example.test/a;b?x=1;c=3;d=4',
            'notice: a=1, b=2, free prose, c=3, d=4',
            'notice: a=1; b=2; free prose; c=3; d=4',
        )
        for raw in bad:
            with self.subTest(raw=raw):
                event=parse_security_once(raw);assert_source_accounting(event)
                self.assertNotIn('DELIMITED_KV',event.syntax)
        url=bad[2]
        url_event=parse_security_once(url);assert_source_accounting(url_event)
        self.assertEqual('SOURCE_PARSED',url_event.status)
        self.assertEqual(
            'https://example.test/a;b?x=1;c=3;d=4',
            url_event.vendor_fields['url'],
        )

    def test_wide_iso_pri_positional_record_preserves_quoted_tokens(self):
        raw=(
            '<134>2023-03-20 17:24:08.959 +0100 '
            'gateway TR 81.2.69.144 443 89.160.20.112 8210 '
            '"-" "-" GET TLSv1.2 example.test HTTP/1.1 404 791 '
            'INTERNAL DEFAULT PROTECTED INVALID /path '
            '"Mozilla/5.0 Test Agent"'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_ISO_PRI+MIXED',event.syntax)
        self.assertIn(
            'Mozilla/5.0 Test Agent',
            event.vendor_fields['generic']['tokens'],
        )
        short=(
            '<134>2023-03-20 17:24:08.959 +0100 '
            'notice 81.2.69.144 89.160.20.112'
        )
        self.assertNotEqual('SOURCE_PARSED',parse_security_once(short).status)

    def test_short_structural_csv_admission_is_evidence_bounded(self):
        quoted=','.join(f'"v{index}"' for index in range(7))
        quoted_event=parse_security_once(quoted);assert_source_accounting(quoted_event)
        self.assertEqual('SOURCE_PARSED',quoted_event.status)
        self.assertIn('GENERIC_POSITIONAL_CSV',quoted_event.syntax)

        network=(
            '2026-10-15 10:00:00,group,action,1,2,'
            '192.0.2.1,,198.51.100.2,,site,12,ALLOW'
        )
        network_event=parse_security_once(network);assert_source_accounting(network_event)
        self.assertEqual('SOURCE_PARSED',network_event.status)
        self.assertIn('GENERIC_POSITIONAL_CSV',network_event.syntax)

        six=','.join(f'"v{index}"' for index in range(6))
        self.assertNotEqual('SOURCE_PARSED',parse_security_once(six).status)
        short_network='a,b,c,d,192.0.2.1,e,198.51.100.2,f,g,h'
        self.assertNotEqual(
            'SOURCE_PARSED',parse_security_once(short_network).status
        )

    def test_semicolon_colon_kv_run_is_structural_without_semantics(self):
        raw=(
            'Organization: Demo; Organization ID: 156646; '
            'Event ID: 458478; Raw Data ID: 1270886879; '
            'Device Name: WIN10-VICTIM; Operating System: Windows 10 Pro'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('SEMICOLON_COLON_KV',event.syntax)
        self.assertEqual(
            'WIN10-VICTIM',event.vendor_fields['generic']['fields']['Device Name']
        )
        short='One: a; Two: b; Three: c; Four: d'
        self.assertNotEqual('SOURCE_PARSED',parse_security_once(short).status)

    def test_spaced_quoted_kv_is_one_value_with_bounded_network_admission(self):
        raw=(
            "<134>1 1639132851.416656563 edge events "
            "kind=vpn msg= 'Peer IP=2.2.2.2 assigned IP 172.25.22.244 '"
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual(
            'Peer IP=2.2.2.2 assigned IP 172.25.22.244 ',
            event.vendor_fields['generic']['kv']['msg'],
        )
        span=next(
            item for item in event.value_spans
            if item.path=='generic.kv.msg'
        )
        self.assertEqual(
            'Peer IP=2.2.2.2 assigned IP 172.25.22.244 ',
            raw.encode()[span.start_byte:span.end_byte].decode(),
        )

        weak=(
            "<134>1 1639132851.416656563 edge events "
            "kind=vpn msg= 'Peer IP=2.2.2.2 only one network atom '"
        )
        self.assertNotEqual(
            'SOURCE_PARSED',parse_security_once(weak).status
        )
        structured_sentence=(
            '<166>Aug 20 2026 08:53:11 edge : %EDGE-6-751025: '
            'Local:203.0.113.10:4500 Remote:198.51.100.25:50466 '
            'IPv4 Address=172.16.58.30 IPv6 address=2001:db8::99 '
            'assigned to session'
        )
        self.assertNotEqual(
            'SOURCE_PARSED',parse_security_once(structured_sentence).status
        )

    def test_quoted_positional_token_allows_one_sentence_punctuation_mark(self):
        raw=(
            '<142>May 10 15:19:05 WatchGuard-Firebox '
            'FVE6035FD3AE3 (2024-05-10T09:49:05) firewall[10]: '
            'msg_id="0205-0003" IKE phase-2 negotiation from '
            "172.16.12.82:500 to 172.16.12.81:500 failed. "
            "Tunnel='tunnel.1' Reason=Received protocol 'AH'. "
            "Expecting 'ESP' in phase-2 proposal."
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_STRUCTURAL+MIXED',event.syntax)
        self.assertIn('AH',event.vendor_fields['generic']['tokens'])
        self.assertNotIn('AH.',event.vendor_fields['generic']['tokens'])

    def test_deep_json_budget_is_bounded_but_above_18(self):
        value=1
        for _ in range(24):
            value={'nested':value}
        raw=json.dumps(value,separators=(',',':'))
        event=parse_security_multipass(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual(1,event.primitive_fields)

        over=1
        for _ in range(34):
            over={'nested':over}
        rejected=parse_security_multipass(
            json.dumps(over,separators=(',',':'))
        )
        self.assertNotEqual('SOURCE_PARSED',rejected.status)
        self.assertTrue(
            any('JSON_DEPTH_OR_FIELD_LIMIT' in issue for issue in rejected.issues)
        )

    def test_large_json_leaf_budget_is_bounded_but_above_1024(self):
        raw=json.dumps(
            {f'field_{index}':index for index in range(2500)},
            separators=(',',':'),
        )
        event=parse_security_multipass(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual(2500,event.primitive_fields)
        self.assertEqual(2500,len(event.value_spans))
        over=json.dumps(
            {f'f{index}':index for index in range(4097)},
            separators=(',',':'),
        )
        rejected=parse_security_multipass(over)
        self.assertNotEqual('SOURCE_PARSED',rejected.status)
        self.assertTrue(
            any('JSON_FIELD_LIMIT' in issue or 'JSON_DEPTH_OR_FIELD_LIMIT' in issue
                for issue in rejected.issues)
        )


if __name__=='__main__':
    unittest.main()
