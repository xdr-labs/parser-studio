#!/usr/bin/env python3
"""Build vendor-documented-cef.v1.json from the ArcSight CEF Implementation Standard page.

Each sample line is cut out of the fetched page text, never retyped. Expected values come from a
CEF tokenizer in this file that shares no code with Parser Studio; it follows the escaping rules
the same page states (header pipe, backslash, extension equals sign, newline). Network access is
needed; run it only to (re)generate the corpus, not in CI.

    python3 evals/golden-corpus/build_cef.py > evals/golden-corpus/vendor-documented-cef.v1.json
"""
import datetime, hashlib, html, json, re, subprocess, sys, tempfile
from html.parser import HTMLParser

URL = ('https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/'
       'cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm')


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


HEADER_NAMES = ['body.cef_version', 'body.cef_device_vendor', 'body.cef_device_product', 'body.cef_device_version',
                'body.cef_signature_id', 'body.cef_name', 'body.cef_severity']


def unescape_header(value):
    return re.sub(r'\\([|\\])', r'\1', value)


def unescape_extension(value):
    return re.sub(r'\\(=|\\|n|r)', lambda m: {'n': '\n', 'r': '\r'}.get(m.group(1), m.group(1)), value)


def cef_values(raw):
    """Header and extension values as the CEF standard defines them (independent of Parser Studio)."""
    start = raw.index('CEF:')
    body = raw[start + 4:]
    fields, buf, i = [], '', 0
    while len(fields) < 7 and i < len(body):
        ch = body[i]
        if ch == '\\' and i + 1 < len(body):
            buf += body[i:i + 2]
            i += 2
            continue
        if ch == '|':
            fields.append(buf)
            buf = ''
        else:
            buf += ch
        i += 1
    extension = body[i:]
    values = {name: unescape_header(value) for name, value in zip(HEADER_NAMES, fields)}
    keys = list(re.finditer(r'(?:(?<=\s)|^)([A-Za-z][A-Za-z0-9_]*)=', extension))
    for index, match in enumerate(keys):
        end = keys[index + 1].start() if index + 1 < len(keys) else len(extension)
        values['body.' + match.group(1)] = unescape_extension(extension[match.end():end].rstrip(' '))
    return values


def pick(text, line):
    hits = [l.strip() for l in text.split('\n') if l.strip() == line]
    if not hits:
        sys.exit('sample not found: ' + line)
    return hits[0]


def case(id_, note, page_sha, raw, wanted):
    values = cef_values(raw)
    missing = [key for key in wanted if key not in values]
    if missing:
        sys.exit('expected fields not in sample: %s' % missing)
    return {
        'id': id_, 'family': 'CEF', 'sampleClass': 'VENDOR_DOCUMENTED', 'publisher': 'OpenText ArcSight',
        'product': 'CEF Implementation Standard - ' + note, 'provenanceUrl': URL,
        'provenance': {'retrievedAt': datetime.date.today().isoformat(), 'pageSha256': page_sha,
                       'extraction': 'verbatim'},
        'rawSample': raw, 'originalSha256': hashlib.sha256(raw.encode()).hexdigest(), 'sampleCount': 1,
        'desiredFields': ', '.join(wanted),
        'goldenSourceValues': [{'sourcePath': key, 'sourceValue': values[key]} for key in wanted],
    }


def main():
    sha, text = fetch(URL)
    cases = []
    raw = pick(text, 'Sep 19 08:26:10 host CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232')
    cases.append(case('arcsight_cef_basic_v0', 'syslog transport example', sha, raw,
                      HEADER_NAMES[1:] + ['body.src', 'body.dst', 'body.spt']))
    raw = pick(text, 'Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1')
    cases.append(case('arcsight_cef_escaped_header_pipe', 'escaped pipe in a header value', sha, raw,
                      ['body.cef_name', 'body.src', 'body.act', 'body.dst']))
    raw = pick(text, 'Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \\= dst=1.1.1.1')
    cases.append(case('arcsight_cef_escaped_equals', 'escaped equals sign in an extension value', sha, raw,
                      ['body.cef_name', 'body.src', 'body.act', 'body.dst']))
    json.dump({'contract': 'parserstudio.golden-corpus.vendor-documented-cef.v1',
               'sourcePolicy': 'VENDOR_DOCUMENTED_PAGE_TEXT_ONLY',
               'purpose': 'Publisher-documented CEF examples cut from the vendor page text; expected values follow '
                          'the escaping rules stated on that page.',
               'cases': cases}, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write('\n')


main()
