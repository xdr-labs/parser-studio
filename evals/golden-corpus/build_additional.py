#!/usr/bin/env python3
"""Build vendor-documented-additional.v1.json from the vendors' own pages.

Each sample is cut out of the fetched page text, never retyped. Expected values
come from a tokenizer in this file that shares no code with Parser Studio.
Network access is needed; run it only to (re)generate the corpus, not in CI.

    python3 evals/golden-corpus/build_additional.py > evals/golden-corpus/vendor-documented-additional.v1.json
"""
import datetime, hashlib, html, json, re, subprocess, sys, tempfile
from html.parser import HTMLParser

ROOT = 'https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Syslog_Event_Types_and_Log_Samples'
SOPHOS = 'https://docs.sophos.com/nsg/sophos-firewall/22.0/syslog/index.html'


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag in ('br', 'p', 'tr', 'pre', 'div', 'li'):
            self.parts.append('\n')


def fetch(url):
    with tempfile.NamedTemporaryFile() as handle:
        code = subprocess.run(['curl', '-sSL', '-m', '60', '-A', 'Mozilla/5.0', url, '-o', handle.name,
                               '-w', '%{http_code}'], capture_output=True, text=True).stdout
        data = open(handle.name, 'rb').read()
    if code != '200':
        sys.exit('HTTP %s for %s' % (code, url))
    parser = _Text()
    parser.feed(data.decode('utf8', 'replace'))
    return hashlib.sha256(data).hexdigest(), html.unescape(''.join(parser.parts))


TOKEN = re.compile(r'([A-Za-z_][\w.]*)=("([^"]*)"|\S*)')


def kv_values(raw, wanted):
    found = {}
    for match in TOKEN.finditer(raw):
        key = match.group(1)
        if key in wanted and key not in found:
            found[key] = match.group(3) if match.group(3) is not None else match.group(2)
    missing = [key for key in wanted if key not in found]
    if missing:
        sys.exit('expected fields not in sample: %s' % missing)
    return [{'sourcePath': key, 'sourceValue': found[key]} for key in wanted]


NBSP = '\u00a0'


def pick(text, pattern):
    """First line matching pattern (leading page indentation ignored); a plain space also matches NBSP."""
    body = pattern[1:] if pattern.startswith('^') else pattern
    loose = '^[ \t\u00a0]*(' + body.replace(' ', '[ \u00a0]') + ')'
    hits = [m.group(1) for m in re.finditer(loose, text, re.M)]
    if len(hits) < 1:
        sys.exit('sample not found: ' + pattern)
    return hits[0]


def cleaned(raw):
    """(sample, extraction) with NBSP turned into a space and recorded as such."""
    return raw.replace(NBSP, ' ').strip(), ('nbsp-to-space' if NBSP in raw else 'verbatim')


def case(id_, family, publisher, product, url, page_sha, raw, extraction, wanted):
    return {
        'id': id_, 'family': family, 'sampleClass': 'VENDOR_DOCUMENTED', 'publisher': publisher, 'product': product,
        'provenanceUrl': url,
        'provenance': {'retrievedAt': datetime.date.today().isoformat(), 'pageSha256': page_sha, 'extraction': extraction},
        'rawSample': raw, 'originalSha256': hashlib.sha256(raw.encode()).hexdigest(), 'sampleCount': 1,
        'desiredFields': ', '.join(wanted), 'goldenSourceValues': kv_values(raw, wanted),
    }


def main():
    meraki_sha, meraki = fetch(ROOT)
    sophos_sha, sophos = fetch(SOPHOS)
    nb = ' '
    cases = []

    raw, how = cleaned(pick(meraki, r'^1380653443\.857790533 MR18 flows allow src=.*$'))
    cases.append(case('meraki_mr_flows_allow', 'FIREWALL', 'Cisco Meraki', 'MR Wireless flows', ROOT, meraki_sha, raw,
                      how, ['src', 'dst', 'mac', 'protocol', 'sport', 'dport']))
    raw, how = cleaned(pick(meraki, r'^1374543986\.038687615 MX84 flows src=.*$'))
    cases.append(case('meraki_mx_flows_pattern', 'FIREWALL', 'Cisco Meraki', 'MX Security Appliance flows', ROOT, meraki_sha,
                      raw, how, ['src', 'dst', 'mac', 'protocol', 'sport', 'dport']))
    raw, how = cleaned(pick(meraki, r'^1792173599\.743929631 MX85 gp_firewall src=.*$'))
    cases.append(case('meraki_mx_gp_firewall', 'FIREWALL', 'Cisco Meraki', 'MX Security Appliance gp_firewall', ROOT,
                      meraki_sha, raw, how, ['src', 'dst', 'vlan', 'protocol', 'sport', 'dport', 'decision']))
    raw, how = cleaned(pick(sophos, r'^device="SFW" date=2018-06-21 time=19:50:23 .*log_component="FTP" log_subtype="Virus".*$'))
    cases.append(case('sophos_sfw_antivirus_ftp', 'ANTIVIRUS', 'Sophos', 'Sophos Firewall 22.0', SOPHOS, sophos_sha, raw,
                      how, ['device', 'date', 'time', 'timezone', 'device_name', 'device_id', 'log_id', 'log_type',
                                   'log_component', 'log_subtype', 'priority', 'fw_rule_id']))
    json.dump({'contract': 'parserstudio.golden-corpus.vendor-documented-additional.v1',
               'sourcePolicy': 'VENDOR_DOCUMENTED_PAGE_TEXT_ONLY',
               'purpose': 'Publisher-documented single-line examples cut from the vendor page text. extraction records '
                          'any whitespace normalization; no sample is retyped.',
               'cases': cases}, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write('\n')


main()
