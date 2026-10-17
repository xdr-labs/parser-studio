#!/usr/bin/env python3
"""Freeze upstream-expected non-JSON Syslog fields and source UTF-8 byte spans.

No Parser Studio TypeScript modules are imported. Only cases with literal raw
bytes and independent upstream expected header semantics can be field-scored.
"""
import ast
import hashlib
import json
import os
import re
from pathlib import Path

STATE = Path.home() / ".local/state/parserstudio-syslog-conformance-20261017"
PINS = Path(__file__).with_name("syslogConformanceSources.pinned.json")
PUBLIC = Path(__file__).with_name("syslogConformanceOracle.v3.pinned.json")
BYTE_INPUT = re.compile(r'\[\]byte\((\x60[^\x60]*\x60|"(?:\\.|[^"\\])*")\)', re.S)
GO_STRING = re.compile(r'"(?:\\.|[^"\\])*"|\x60[^\x60]*\x60', re.S)
RFC3164 = re.compile(
    r'^<(?P<pri>[0-9]{1,3})>(?P<month>[A-Z][a-z]{2}) +'
    r'(?P<day>[0-9]{1,2}) +(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) +'
    r'(?P<hostname>[^ ]+) +(?P<message>.*)$', re.S
)
RFC5424 = re.compile(r'^<([0-9]{1,3})>([1-9][0-9]{0,2}) ')
KNOWN_FIELDS = ('hostname', 'appname', 'procid', 'msgid', 'timestamp', 'message')
MAX_RAW = 65536


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def freeze(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError("Frozen independent oracle was changed")
        return
    fd = os.open(path, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)


def unquote(literal: str) -> str:
    if literal.startswith(chr(96)):
        return literal[1:-1]
    if re.search(r'\\(?:x|[0-7]{3}|U[0-9]|u[0-9])', literal):
        raise ValueError("Potentially byte-encoded Go literal is not unambiguous Unicode")
    value = ast.literal_eval(literal)
    if not isinstance(value, str):
        raise ValueError("Not a literal source string")
    return value


def extract_literal(block: str, otel=False) -> str | None:
    if not otel:
        token = BYTE_INPUT.search(block)
        if token is None:
            return None
        return unquote(token.group(1))
    entry = re.search(r'\bBody:\s*(\x60[^\x60]*\x60|"(?:\\.|[^"\\])*")\s*,', block, re.S)
    if not entry:
        return None
    return unquote(entry.group(1))


def expected_go(block: str, format_id: str) -> dict:
    result = {}
    if format_id == "influx_rfc3164":
        for field in ('Priority', 'Facility', 'Severity'):
            m = re.search(r'\b'+field+r':\s*syslogtesting\.Uint8Address\(([0-9]+)\)', block)
            if m:
                result[field.lower()] = int(m.group(1))
        for field in ('Hostname', 'Appname', 'ProcID', 'MsgID', 'Message'):
            m = re.search(r'\b'+field+r':\s*syslogtesting\.StringAddress\(('
                          r'\x60[^\x60]*\x60|"(?:\\.|[^"\\])*"'
                          r')\)', block, re.S)
            if m:
                result[field.lower()] = unquote(m.group(1))
        m = re.search(r'Timestamp:\s*syslogtesting\.TimeParse\(time\.Stamp,\s*("(?:\\.|[^"\\])*")\)', block)
        if m:
            result['timestamp'] = unquote(m.group(1))
    elif format_id == "influx_rfc5424":
        for field in ('Version', 'Priority'):
            m = re.search(r'\bSet'+field+r'\(([0-9]+)\)', block)
            if m:
                result[field.lower()] = int(m.group(1))
        for field in ('Timestamp', 'Hostname', 'Appname', 'ProcID', 'MsgID', 'Message'):
            m = re.search(r'\bSet'+field+r'\(\s*(\x60[^\x60]*\x60|"(?:\\.|[^"\\])*")\s*\)', block, re.S)
            if m:
                result[field.lower()] = unquote(m.group(1))
    else:
        # Read only the upstream expected Attributes section (not input).
        marker = block.find("Attributes: map[string]any{")
        if marker < 0:
            return {}
        expected = block[marker:]
        for field in ('priority', 'version'):
            match = re.search(r'"'+field+r'"\s*:\s*([0-9]+)', expected)
            if match:
                result[field] = int(match.group(1))
        for field in ('hostname', 'appname', 'proc_id', 'msg_id', 'message'):
            match = re.search(r'"'+field+r'"\s*:\s*(\x60[^\x60]*\x60|"(?:\\.|[^"\\])*")\s*,', expected, re.S)
            if match:
                result[{'proc_id':'procid','msg_id':'msgid'}.get(field,field)] = unquote(match.group(1))
    if format_id == "otel_syslog":
        # This comes from the independent upstream expected Entry.Timestamp,
        # not from the message under test or Parser Studio's interpretation.
        m = re.search(
            r'Timestamp:\s*time\.Date\(\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),'
            r'\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),'
            r'\s*time\.UTC\s*\)', block)
        if m:
            result['timestamp_components'] = list(map(int, m.groups()))
    return result


def value_span(raw: str, name: str, value: str, start: int, end: int) -> dict:
    if raw[start:end] != value:
        raise ValueError("Expected source span is not exact")
    return {'name': name, 'type': 'string', 'value': value,
            'start_byte': len(raw[:start].encode('utf-8', 'strict')),
            'end_byte': len(raw[:end].encode('utf-8', 'strict'))}


def parse_rfc3164(raw: str, expected: dict) -> list:
    match = RFC3164.match(raw)
    if not match:
        raise ValueError("No independently segmentable RFC3164 record")
    pri = int(match['pri'])
    if expected.get('priority') != pri:
        raise ValueError("Source/upstream PRI disagreement")
    if expected.get('hostname') != match['hostname']:
        raise ValueError("Source/upstream hostname disagreement")
    if expected.get('facility', pri//8) != pri//8 or expected.get('severity', pri%8) != pri%8:
        raise ValueError("Source/upstream PRI decomposition disagreement")
    stamp = expected.get('timestamp')
    if stamp is None or not re.fullmatch(
            r'[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2}', stamp):
        raise ValueError("Upstream timestamp source truth unavailable")
    fields = []
    for key in ('pri', 'month', 'day', 'time', 'hostname'):
        if key == 'pri':
            fields.append(value_span(raw, key, match[key], match.start(key), match.end(key)))
        else:
            fields.append(value_span(raw, key, match[key], match.start(key), match.end(key)))
    # The explicit tag/procid is only accepted when upstream independently lists it.
    tail = match['message']
    if expected.get('appname') is not None:
        t = re.match(r'^([A-Za-z0-9_.@/\\-]{1,128})(?:\[([0-9]{1,10})\])?:[ \t]*(.*)$', tail, re.S)
        if not t or t.group(1) != expected['appname']:
            raise ValueError("Upstream/lexical BSD tag mismatch")
        if expected.get('procid') is not None and t.group(2) != expected['procid']:
            raise ValueError("Upstream/lexical BSD procid mismatch")
        origin = match.start('message')
        fields.append(value_span(raw, 'appname', t.group(1), origin+t.start(1), origin+t.end(1)))
        if t.group(2) is not None:
            fields.append(value_span(raw, 'procid', t.group(2), origin+t.start(2), origin+t.end(2)))
        remainder = t.group(3)
        message_start = origin + t.start(3)
    else:
        remainder = tail
        message_start = match.start('message')
    if expected.get('message') is not None:
        if expected['message'] != remainder:
            raise ValueError("Upstream/lexical BSD message mismatch")
        fields.append(value_span(raw, 'message', remainder, message_start,
                                 message_start+len(remainder)))
    return fields


def parse_rfc5424(raw: str, expected: dict) -> list:
    prefix = RFC5424.match(raw)
    if not prefix:
        raise ValueError("No independently segmentable RFC5424 prefix")
    if int(prefix[1]) != expected.get('priority') or int(prefix[2]) != expected.get('version'):
        raise ValueError("Source/upstream PRI or version disagreement")
    fields = [
        value_span(raw, 'pri', prefix[1], prefix.start(1), prefix.end(1)),
        value_span(raw, 'version', prefix[2], prefix.start(2), prefix.end(2)),
    ]
    pos = prefix.end()
    for key in ('timestamp', 'hostname', 'appname', 'procid', 'msgid'):
        end = raw.find(' ', pos)
        if end < pos:
            raise ValueError("Mandatory RFC5424 header separator missing")
        token = raw[pos:end]
        if token != '-':
            if key == 'timestamp' and 'timestamp_components' in expected:
                from datetime import datetime, timezone
                year, month, day, hour, minute, sec, nanosec = expected['timestamp_components']
                try:
                    observed = datetime.fromisoformat(token.replace('Z', '+00:00'))
                    required = datetime(year, month, day, hour, minute, sec,
                                        nanosec // 1000, tzinfo=timezone.utc)
                except ValueError as exc:
                    raise ValueError("Upstream timestamp is not comparable") from exc
                if observed != required:
                    raise ValueError("Independent time.Date timestamp differs")
            elif expected.get(key) != token:
                raise ValueError("Upstream expected header token differs")
            fields.append(value_span(raw, key, token, pos, end))
        elif key in expected:
            raise ValueError("NILVALUE contradicts upstream expected header")
        pos = end+1
    # Explicit structured-data raw range, but not certified semantic SD-PARAM decoding.
    if raw[pos:pos+1] == '-':
        sd_end = pos+1
    elif raw[pos:pos+1] == '[':
        sd_end = pos
        quoted = False
        escaped = False
        for index in range(pos,len(raw)):
            char = raw[index]
            if quoted and escaped:
                escaped = False
                continue
            if quoted and char == '\\\\':
                escaped = True
                continue
            if char == '"':
                quoted = not quoted
            if char == ']' and not quoted:
                sd_end = index+1
                if raw[sd_end:sd_end+1] != '[':
                    break
        if sd_end <= pos or quoted or escaped:
            raise ValueError("Unfinished upstream structured data")
    else:
        raise ValueError("Structured data section is missing")
    fields.append(value_span(raw, 'structured_data_raw', raw[pos:sd_end], pos, sd_end))
    if sd_end < len(raw):
        if raw[sd_end] != ' ':
            raise ValueError("Malformed MSG separator")
        msg = raw[sd_end+1:]
        if expected.get('message') != msg:
            raise ValueError("Independent upstream MSG differs")
        fields.append(value_span(raw, 'message', msg, sd_end+1, len(raw)))
    elif expected.get('message') is not None:
        raise ValueError("Missing upstream MSG bytes")
    return fields


def case_blocks(text: str, fmt: str) -> list:
    indent = '\\t\\t' if fmt == 'otel_syslog' else '\\t'
    return re.findall(r'(?ms)^'+indent+r'\{\s*\n(.*?)^'+indent+r'\},', text)


def case_valid(block: str, fmt: str) -> bool:
    if fmt == 'otel_syslog':
        return True
    match = re.search(r'(?m)^\s*(?:valid:\s*)?(true|false),\s*$', block)
    return match is not None and match.group(1) == 'true'


def main() -> None:
    public = PINS.read_bytes()
    manifest = json.loads(public)
    if public != (STATE / 'sources.pinned.json').read_bytes():
        raise RuntimeError("Private/public original-source pins disagree")
    rows = []
    counts = {}
    for source in manifest['files']:
        original = (STATE/'upstream'/(source['id']+'.go')).read_bytes()
        if sha(original) != source['sha256']:
            raise RuntimeError("Upstream test fixture SHA drift")
        blocks = case_blocks(original.decode('utf8'), source['id'])
        bucket = {'all':0,'scorable':0,'negative':0,'unscorable':0,
                  'field_triples':0,'source_literal':0}
        for i, block in enumerate(blocks):
            bucket['all'] += 1
            candidate = {'id':f"{source['id']}-{i:04d}", 'source_id':source['id'],
                         'split':source['split'], 'test_case_ordinal':i}
            try:
                raw = extract_literal(block,source['id']=='otel_syslog')
                if raw is None:
                    raise ValueError("Source is dynamic or not a literal")
                data = raw.encode('utf8','strict')
                if not data or len(data)>MAX_RAW or b'\\x00' in data:
                    raise ValueError("Unusable source bytes for single-event scoring")
                candidate.update({'raw':raw,'raw_sha256':sha(data),'raw_bytes':len(data)})
                bucket['source_literal']+=1
                valid = case_valid(block,source['id'])
                candidate['upstream_accepts'] = valid
                if not valid:
                    bucket['negative']+=1
                    candidate['status']='NEGATIVE_ONLY'
                    candidate['fields']=[]
                else:
                    expected = expected_go(block,source['id'])
                    if source['id']=='influx_rfc3164':
                        fields = parse_rfc3164(raw,expected)
                    else:
                        fields = parse_rfc5424(raw,expected)
                    # Every reference triple is verified against original UTF-8 bytes.
                    for f in fields:
                        segment = data[f['start_byte']:f['end_byte']]
                        if segment.decode('utf8','strict') != f['value']:
                            raise ValueError("Byte span did not replay to expected value")
                    candidate['status']='INDEPENDENT_UPSTREAM_CONFORMANCE_FIELDS'
                    candidate['fields']=fields
                    candidate['expected_grammar']='rfc3164' if source['id']=='influx_rfc3164' else 'rfc5424'
                    bucket['scorable']+=1
                    bucket['field_triples']+=len(fields)
            except (ValueError,UnicodeError,SyntaxError,OverflowError) as exc:
                candidate.setdefault('raw',None)
                candidate['status']='UNSCORABLE'
                candidate['fields']=[]
                candidate['reason_code']=type(exc).__name__
                bucket['unscorable']+=1
            rows.append(candidate)
        counts[source['id']]=bucket
    if sum(x['all'] for x in counts.values())!=len(rows):
        raise RuntimeError("Case accounting mismatch")
    data=(json.dumps(rows,ensure_ascii=True,separators=(',',':'))+'\n').encode()
    freeze(STATE/'records-and-expected.v3.pinned.json',data)
    summary={'schema':'syslog-conformance-golden-v3',
             'stage':'FROZEN_BEFORE_ANY_BASELINE_OR_CANDIDATE_SCORING',
             'v1_exclusion_correction':'Exploratory v1 raw-backtick handling and v2 multiline Go method-chaining qualification were incomplete; both frozen snapshots retained',
             'source_manifest_sha256':sha(public),'private_oracle_sha256':sha(data),
             'source_repo_count':len(set(x['repository'] for x in manifest['files'])),
             'source_files':len(manifest['files']),
             'all_cases':len(rows),
             'scorable':sum(x['scorable'] for x in counts.values()),
             'negative_only':sum(x['negative'] for x in counts.values()),
             'unscorable':sum(x['unscorable'] for x in counts.values()),
             'source_field_triples':sum(x['field_triples'] for x in counts.values()),
             'groups':counts,
             'qualification':'UPSTREAM_LIBRARY_TEST_EXPECTATIONS_NOT_AUTHENTIC_DEVICE',
             'native_stellar':'NOT_VERIFIED','manufacturer_semantics':'NOT_CERTIFIED'}
    s=(json.dumps(summary,indent=2)+'\n').encode()
    freeze(STATE/'oracle-summary.v3.pinned.json',s)
    if PUBLIC.exists() and PUBLIC.read_bytes()!=s:
        raise RuntimeError("Frozen public oracle changed")
    PUBLIC.write_bytes(s)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
