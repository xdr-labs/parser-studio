"""Public security-log generalization regressions; source extraction only.

Samples are minimized from public integration fixtures/documentation. Assertions
cover literal source structure, value identity and exact byte accounting only;
semantic field meaning is deliberately not scored.
"""
import json
import unittest

from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structured_source import extract_rfc5424


class PublicSecurityGeneralization20261015(unittest.TestCase):
    def parse(self, raw):
        event = parse_security_multipass(raw)
        self.assertEqual(raw, event.raw)
        assert_source_accounting(event)
        return event

    def assert_profile_span_values(self, event):
        source = event.raw.encode('utf8')
        for span in event.value_spans:
            node = event.vendor_fields
            for segment in span.path.split('.'):
                node = node[int(segment)] if isinstance(node, list) else node[segment]
            if isinstance(node, list):
                continue
            self.assertEqual(
                str(node),
                source[span.start_byte:span.end_byte].decode('utf8'),
                span.path,
            )

    def test_f5_asm_rfc3164_tag_without_space_before_cef(self):
        raw = (
            '<131>Sep 19 13:53:34 bigip-4.example ASM:'
            'CEF:0|F5|ASM|11.3.0|200021069|Automated client access "wget"|5|'
            'dvchost=bigip-4.example dvc=172.16.73.34 cs1=topaz4-web4 '
            'cs1Label=policy_name act=blocked src=10.4.1.101 spt=52975 '
            'dst=10.4.1.200 dpt=80 requestMethod=GET app=HTTP'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('ASM', event.vendor_fields['syslog']['tag'])
        self.assertEqual('F5', event.vendor_fields['body']['cef_header']['vendor'])
        self.assertEqual(
            '10.4.1.101', event.vendor_fields['body']['cef_extension']['src']
        )
        self.assertEqual('HTTP', event.vendor_fields['body']['cef_extension']['app'])

    def test_juniper_rfc5424_msgid_adjacent_structured_data(self):
        raw = (
            '<14>1 2012-12-20T17:40:07.758-06:00 tok-srx100 RT_FLOW - '
            'RT_FLOW_SESSION_CREATE[junos@2636.1.1.1.2.41 reason="unset" '
            'source-address="10.140.2.62" source-port="61718" '
            'destination-address="10.199.5.255" destination-port="161" '
            'service-name="None" protocol-id="17" policy-name="trust_to_trust"]'
        )
        strict = extract_rfc5424(raw)
        self.assertIsNotNone(strict)
        self.assertNotEqual([], strict[0].issues)
        adjacent = extract_rfc5424(raw, allow_adjacent_sd=True)
        self.assertIsNotNone(adjacent)
        self.assertEqual([], adjacent[0].issues)
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual(
            'RT_FLOW_SESSION_CREATE', event.vendor_fields['syslog']['msgid']
        )
        structured = event.vendor_fields['syslog']['structured_data']
        sd = structured['junos@2636.1.1.1.2.41']
        self.assertEqual('10.140.2.62', sd['source-address'])
        self.assertEqual('10.199.5.255', sd['destination-address'])
        self.assertEqual('trust_to_trust', sd['policy-name'])

    def test_zscaler_rfc5424_leef20_implicit_tab_delimiter(self):
        raw = (
            '<4>1 2019-11-21T13:44:37Z ZSCALER NSS - - - '
            'LEEF:2.0|Zscaler|NSS|3.6|ALLOW|'
            'cat=firewall\tusrName=jane.doe\tsrc=203.0.113.10\tdst=198.51.100.20'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        header = event.vendor_fields['body']['leef_header']
        extension = event.vendor_fields['body']['leef_extension']
        self.assertEqual('Zscaler', header['vendor'])
        self.assertNotIn('delimiter', header)
        self.assertEqual('firewall', extension['cat'])
        self.assertEqual('198.51.100.20', extension['dst'])

    def test_existing_sophos_pri_kv_and_netskope_cef_stay_exact(self):
        sophos = (
            '<30>device="SFW" date=2020-05-18 time=14:38:48 timezone="CEST" '
            'device_name="XG230" log_type="Anti-Spam" log_component="SMTP" '
            'reason="Email has been accepted by Device and queued for scanning." '
            'src_ip="" dst_ip="" protocol="TCP" src_port=0 dst_port=0'
        )
        event = self.parse(sophos)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('SMTP', event.vendor_fields['body']['log_component'])

        netskope = (
            '<14>Sep 01 14:39:36 netskopece '
            'CEF:0|Netskope|Example Tenant|NULL|application|NULL|Unknown|'
            'act=Download appcategory=Cloud Storage browser=Safari '
            'dst=192.0.2.20 src=198.51.100.11 suser=julia.moore@example.com'
        )
        event = self.parse(netskope)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('Netskope', event.vendor_fields['body']['cef_header']['vendor'])
        self.assertEqual(
            'Cloud Storage', event.vendor_fields['body']['cef_extension']['appcategory']
        )

    def test_meraki_epoch_flow_profile_extracts_header_and_all_kv(self):
        raw = (
            '<134>1 1563246850.048798929 Head_office_Appliance flows allow '
            'src=192.168.254.135 dst=192.168.254.7 mac=E8:E8:B7:35:4A:C2 '
            'protocol=udp sport=33787 dport=35'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('MERAKI_PROFILE', event.syntax)
        self.assertEqual('flows', event.vendor_fields['meraki_header']['record_type'])
        self.assertEqual(['allow'], event.vendor_fields['meraki']['tokens'])
        self.assertEqual('192.168.254.135', event.vendor_fields['meraki']['kv']['src'])
        self.assertEqual('35', event.vendor_fields['meraki']['kv']['dport'])
        self.assert_profile_span_values(event)

    def test_watchguard_traffic_profile_preserves_positional_and_kv_values(self):
        raw = (
            'Jun 17 20:59:55 TXX-PoE firewall: msg_id="3000-0148" Allow '
            '0-SSL-VPN VLAN123 60 tcp 20 63 1.1.1.1 2.2.2.2 33564 8006 '
            'offset 10 S 147268851 win 61690 src_user="me@Firebox-DB" '
            '(Allow SSLVPN-TEST-00)'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('WATCHGUARD_FIREBOX_TRAFFIC_PROFILE', event.syntax)
        body = event.vendor_fields['watchguard']
        self.assertEqual('3000-0148', body['kv']['msg_id'])
        self.assertEqual('me@Firebox-DB', body['kv']['src_user'])
        self.assertIn('1.1.1.1', body['tokens'])
        self.assertIn('2.2.2.2', body['tokens'])
        self.assertEqual(['Allow SSLVPN-TEST-00'], body['groups'])
        self.assert_profile_span_values(event)

    def test_juniper_legacy_rtflow_profile_preserves_positional_values(self):
        raw = (
            'Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: '
            'session created 192.168.83.99/40275->192.168.32.1/161 None '
            '192.168.83.99/40275->192.168.32.1/161 None None 17 '
            'allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('JUNIPER_RT_FLOW_PROFILE', event.syntax)
        body = event.vendor_fields['juniper']
        self.assertEqual('RT_FLOW_SESSION_CREATE', body['event'])
        self.assertEqual('session', body['tokens'][0])
        self.assertIn(
            '192.168.83.99/40275->192.168.32.1/161',
            body['tokens'],
        )
        self.assertEqual('vlan.255', body['tokens'][-1])
        self.assert_profile_span_values(event)

    def test_meraki_ids_and_url_variants_keep_all_visible_source_values(self):
        ids = (
            '1 1788735305.123456789 MX68-EDGE ids-alerts '
            'signature=1:2012034:1 priority=1 timestamp=1788735305.12 '
            'direction=ingress protocol=tcp/ip src=185.220.101.5:41200 '
            'dst=192.168.128.10:80 message: ET SCAN Suspicious User-Agent'
        )
        event = self.parse(ids)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('ids-alerts', event.vendor_fields['meraki_header']['record_type'])
        self.assertEqual('1:2012034:1', event.vendor_fields['meraki']['kv']['signature'])
        self.assertEqual('ET', event.vendor_fields['meraki']['tokens'][-4])

        urls = (
            '1374543213.342705328 MX84 urls : '
            'src=192.168.1.186:63735 dst=69.58.188.40:80 '
            'mac=58:1F:AA:CE:61:F2 request: GET https://example.test/'
        )
        event = self.parse(urls)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('urls', event.vendor_fields['meraki_header']['record_type'])
        self.assertEqual('192.168.1.186:63735', event.vendor_fields['meraki']['kv']['src'])
        self.assertIn('GET', event.vendor_fields['meraki']['tokens'])

    def test_watchguard_extended_header_and_proxy_traffic_variants(self):
        raw = (
            '<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 '
            '(2024-01-19T08:48:15) firewall: msg_id="1BFF-000F" Allow '
            '1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25 '
            'msg="SMTP request" proxy_act="SMTP-Outgoing.1" '
            'rcvd_bytes="272" sent_bytes="282" '
            'sender="tester@testnet.com" recipients="wg@localhost" '
            '(SMTP-proxy-00)'
        )
        event = self.parse(raw)
        self.assertEqual('SOURCE_PARSED', event.status)
        header = event.vendor_fields['watchguard_header']
        body = event.vendor_fields['watchguard']
        self.assertEqual('139', header['pri'])
        self.assertEqual('FVE6035FD3AE3', header['serial'])
        self.assertEqual('2024-01-19T08:48:15', header['device_time'])
        self.assertEqual('1BFF-000F', body['kv']['msg_id'])
        self.assertEqual('SMTP request', body['kv']['msg'])
        self.assertEqual('tester@testnet.com', body['kv']['sender'])
        self.assertEqual(['SMTP-proxy-00'], body['groups'])

        pid = (
            '<142>May 20 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 '
            '(2024-01-10T09:49:17) firewall[10]: msg_id="3000-0150" Deny '
            '1-Trusted 0-External 1440 tcp 20 61 10.0.1.2 192.168.130.126 '
            '55810 80 offset 5 A 447868619 win 54 severity="4" '
            'msg="IPS detected" (HTTP-00)'
        )
        event = self.parse(pid)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('firewall[10]', event.vendor_fields['watchguard_header']['app_tag'])
        self.assertEqual('IPS detected', event.vendor_fields['watchguard']['kv']['msg'])

    def test_edr_json_holdouts_keep_nested_values_types_and_spans(self):
        sentinelone = json.dumps({
            'id':'threat-001',
            'mitigationStatus':[],
            'threatInfo':{
                'analystVerdict':'false_positive',
                'threatName':'Suspicious Tool',
                'confidenceLevel':'malicious',
            },
            'agentDetectionInfo':{
                'agentUuid':'agent-001',
                'agentIpV4':'192.0.2.44',
            },
            'resolved':False,
            'score':87,
            'nullable':None,
        },separators=(',',':'))
        event = self.parse(sentinelone)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual('JSON', event.syntax)
        self.assertEqual(
            'false_positive',
            event.vendor_fields['threatInfo']['analystVerdict'],
        )
        self.assertIs(event.vendor_fields['resolved'], False)
        self.assertEqual(87, event.vendor_fields['score'])
        self.assertIsNone(event.vendor_fields['nullable'])
        self.assertEqual(event.primitive_fields, len(event.value_spans))

        crowdstrike = json.dumps({
            'event':{
                'AgentIdString':'fffffffff33333',
                'HostnameField':'UKCHUDL00206',
                'SessionId':'1111-fffff-4bb4-99c1-74c13cfc3e5a',
                'StartTimestamp':1698932494,
                'UserName':'admin.rose@example.com',
            },
            'metadata':{
                'customerIDString':'abcabcabc22221',
                'eventCreationTime':1698932494000,
                'eventType':'RemoteResponseSessionStartEvent',
                'offset':1,
                'version':'1.0',
            },
        },separators=(',',':'))
        event = self.parse(crowdstrike)
        self.assertEqual('SOURCE_PARSED', event.status)
        self.assertEqual(
            'RemoteResponseSessionStartEvent',
            event.vendor_fields['metadata']['eventType'],
        )
        self.assertEqual(1698932494000, event.vendor_fields['metadata']['eventCreationTime'])
        self.assertEqual(event.primitive_fields, len(event.value_spans))

    def test_narrow_repairs_do_not_promote_unstructured_lookalikes(self):
        bad = (
            '<131>Sep 19 13:53:34 bigip-4.example ASM:not-cef src=10.0.0.1',
            '<14>1 2012-12-20T17:40:07.758-06:00 tok-srx100 RT_FLOW - X[broken',
            'LEEF:2.0|Zscaler|NSS|3.6|ALLOW|cat=firewall src=1.1.1.1',
            '<134>1 1563246850.048798929 MX68 flows allow src=192.0.2.1 protocol=tcp',
            'Jun 17 20:59:55 TXX-PoE firewall: msg_id="3000-0148" Allow '
            'Trusted External tcp 192.0.2.1 443',
            'Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: '
            'session created without an endpoint tuple',
        )
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                self.assertNotEqual('SOURCE_PARSED', self.parse(raw).status)


if __name__ == '__main__':
    unittest.main()
