#!/usr/bin/env python3
"""Build vendor-published-text-cisco-asa.v1.json.

Samples are Cisco's own published ASA syslog examples (Cisco document 116149).
They were read from the live page's TEXT (WebFetch extraction on 2026-11-11).
The page's raw bytes could NOT be captured: the sandbox network path to
cisco.com redirects to a support index page, and defeating that bot gate is not
permitted. Therefore:

  * sampleClass is VENDOR_PUBLISHED_TEXT, NOT VENDOR_DOCUMENTED (which requires
    a raw page-byte hash);
  * provenance.pageSha256 is null and pageBytesCaptured is false;
  * originalSha256 is the SHA-256 of the assembled sample line only.

Cisco's page wraps each example across two printed lines. The assembled sample
joins the printed fragments with ONE space; the fragments are kept verbatim.
The interface names are published but not extracted (the project schema caps a
Regex pattern at 256 characters). Expected values are hand-authored from Cisco's documented message grammar
(message 302013: Built {inbound|outbound} TCP connection_id for
interface:real-address/real-port (mapped-address/mapped-port) to
interface:real-address/real-port (mapped-address/mapped-port)); they share no
code with Parser Studio and are never read back from generated Ruby.

    python3 evals/golden-corpus/build_cisco_asa_published_text.py \
      > evals/golden-corpus/vendor-published-text-cisco-asa.v1.json
"""
import hashlib, json, sys

URL = 'https://www.cisco.com/c/en/us/support/docs/security/adaptive-security-appliance-asa-software/116149-qanda-ASA-00.html'
BLOCKER = ('cisco.com page bytes not capturable from the sandbox (redirects to a support index; '
           'circumventing the bot gate is not permitted). Text was read via WebFetch.')


def case(id_, scenario, fragments, expected, stellar, matches=True):
    raw = ' '.join(fragments)
    return {
        'id': id_, 'family': 'FIREWALL', 'sampleClass': 'VENDOR_PUBLISHED_TEXT',
        'publisher': 'Cisco', 'product': 'Cisco ASA', 'provenanceUrl': URL,
        'provenance': {
            'documentId': '116149', 'documentUpdated': 'August 19, 2015', 'retrievedAt': '2026-11-11',
            'retrievalMethod': 'WebFetch page-text extraction', 'pageBytesCaptured': False,
            'pageSha256': None, 'blocker': BLOCKER, 'scenario': scenario,
            'extraction': 'published-line-wrap-joined-with-single-space', 'publishedFragments': fragments,
        },
        'rawSample': raw, 'originalSha256': hashlib.sha256(raw.encode()).hexdigest(), 'sampleCount': 1,
        'expectedMatch': matches, 'expectedFields': expected, 'expectedStellarFields': stellar,
    }


def main():
    cases = [
        case('cisco_asa_302013_inbound_outside_to_inside', 'Traffic through the ASA from the outside host to the inside host',
             ['%ASA-6-302013: Built inbound TCP connection 11 for outside:10.1.2.1/21647',
              '(10.1.2.1/21647) to inside:10.1.1.2/22 (10.1.1.2/22)'],
             {'event_id': '302013', 'direction': 'inbound', 'protocol': 'TCP', 'connection_id': '11',
              'src_ip': '10.1.2.1', 'src_port': '21647', 
              'dst_ip': '10.1.1.2', 'dst_port': '22', 'dst_mapped_ip': '10.1.1.2'},
             {'srcip': '10.1.2.1', 'dstip': '10.1.1.2', 'protocol': 'TCP'}),
        case('cisco_asa_302013_outbound_outside_to_inside', 'Traffic through the ASA from the inside host to the outside host',
             ['%ASA-6-302013: Built outbound TCP connection 9 for outside:10.1.2.1/22 (10.1.2.1/22)',
              'to inside:10.1.1.2/53496 (10.1.1.2/53496)'],
             {'event_id': '302013', 'direction': 'outbound', 'protocol': 'TCP', 'connection_id': '9',
              'src_ip': '10.1.2.1', 'src_port': '22', 
              'dst_ip': '10.1.1.2', 'dst_port': '53496', 'dst_mapped_ip': '10.1.1.2'},
             {'srcip': '10.1.2.1', 'dstip': '10.1.1.2', 'protocol': 'TCP'}),
        case('cisco_asa_302013_inbound_mapped_destination_differs', 'Same-security interfaces, traffic from the outside host to the inside host',
             ['%ASA-6-302013: Built inbound TCP connection 1 for outside:10.1.2.1/17891 (10.1.2.1/17891)',
              'to inside:10.1.1.2/23 (10.1.2.5/23)'],
             {'event_id': '302013', 'direction': 'inbound', 'protocol': 'TCP', 'connection_id': '1',
              'src_ip': '10.1.2.1', 'src_port': '17891', 
              'dst_ip': '10.1.1.2', 'dst_port': '23', 'dst_mapped_ip': '10.1.2.5'},
             {'srcip': '10.1.2.1', 'dstip': '10.1.1.2', 'protocol': 'TCP'}),
        case('cisco_asa_302014_teardown_is_a_different_message', 'Teardown of the same-security scenario 2 connection',
             ['%ASA-6-302014: Teardown TCP connection 1 for outside:10.1.2.1/17891 to inside:10.1.1.2/23',
              'duration 0:00:08 bytes 165 TCP FIN'],
             {}, {}, matches=False),
    ]
    json.dump({
        'contract': 'parserstudio.golden-corpus.vendor-published-text.v1',
        'sourcePolicy': 'VENDOR_PUBLISHED_TEXT_NO_PAGE_BYTES',
        'purpose': 'Cisco-published ASA syslog examples whose page bytes could not be hashed. They are NOT VENDOR_DOCUMENTED '
                   'and are not counted as such; the Ruby 2.4.9 gate executes them against hand-authored expected values.',
        'cases': cases,
    }, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write('\n')


main()
