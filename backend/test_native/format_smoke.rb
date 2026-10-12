# Synthetic fixture coverage only — not production Fluentd or Stellar target E2E.
require 'json'
require_relative 'synthetic_fixture_guard'
require 'time'

def assert(condition, message)
  raise "FAILED #{message}" unless condition
end

def execute_parser(directory, slug, raw)
  path = File.join(directory, "customized_#{slug}")
  parser_class = Class.new
  parser_class.class_eval(SyntheticFixtureGuard.read_source(path), path, 1)
  parser = parser_class.new
  count = 0
  result_time = nil
  result_record = nil
  parser.parse(raw) do |time, record|
    count += 1
    result_time, result_record = time, record
  end
  assert(count == 1, "#{slug}: exactly one callback")
  [result_time, result_record]
end

folder = ARGV.fetch(0)

# CSV: quoted values, unmatched/malformed row are not silently accepted.
_, csv = execute_parser(folder, "sample_csv", %q{192.0.2.9,443,"deny"})
assert(csv["srcip"] == "192.0.2.9", "CSV source IP")
assert(csv["dstport"] == 443, "CSV typed port")
assert(csv["stellar_log_index"] == "threat", "CSV threat classification")
_, csv_bad = execute_parser(folder, "sample_csv", "192.0.2.1,443")
assert(csv_bad["parser_err_msg"] == "ArgumentError", "CSV column count error")

# RFC5424: explicit timestamp, typed nested body and PRI range checking.
syslog_input = "<165>1 2026-10-12T01:02:03Z edge01 firewall 123 ID42 - src_ip=198.51.100.5 action=deny"
time, syslog = execute_parser(folder, "sample_syslog", syslog_input)
assert(syslog["srcip"] == "198.51.100.5", "RFC5424 KV body")
assert(syslog["stellar_log_index"] == "threat", "RFC5424 classification")
assert(syslog["timestamp"].is_a?(Integer), "RFC5424 timestamp integer milliseconds")
assert(time.utc.iso8601 == "2026-10-12T01:02:03Z", "RFC5424 actual callback time")
_, syslog_bad = execute_parser(folder, "sample_syslog", "<192>1 2026-10-12T01:02:03Z h a 1 ID - src_ip=192.0.2.5")
assert(syslog_bad.key?("parser_err_msg"), "RFC5424 invalid PRI")

# CEF: CEF escaped header separator and strict bounded extension KV subset.
cef_input = 'CEF:0|Synthetic|FW|1|42|Denied\|Policy|8|src=192.0.2.7 dst=198.51.100.1 dpt=443 act=deny'
_, cef = execute_parser(folder, "sample_cef", cef_input)
assert(cef["srcip"] == "192.0.2.7", "CEF srcip")
assert(cef["dstport"] == 443, "CEF port")
assert(cef["stellar_log_index"] == "threat", "CEF action")
_, cef_bad = execute_parser(folder, "sample_cef", "CEF:0|Synthetic|FW|1|42|Denied|8|src=192.0.2.7 straygarbage")
assert(cef_bad.key?("parser_err_msg"), "CEF malformed extension must fail, not lose data")

# LEEF 1.0 (TAB) and 2.0 (declared separator).
leef1 = "LEEF:1.0|Synthetic|FW|1|500|src=192.0.2.8\tdstPort=80\tact=deny"
_, rec1 = execute_parser(folder, "sample_leef", leef1)
assert(rec1["srcip"] == "192.0.2.8", "LEEF 1.0 source")
assert(rec1["stellar_log_index"] == "threat", "LEEF 1.0 classification")
leef2 = "LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=443^act=allow"
_, rec2 = execute_parser(folder, "sample_leef", leef2)
assert(rec2["srcip"] == "203.0.113.8", "LEEF 2.0 source")
assert(rec2["stellar_log_index"] == "session", "LEEF 2.0 classification")
_, bad_delimiter = execute_parser(folder, "sample_leef", "LEEF:2.0|Synthetic|FW|1|501|::|src=192.0.2.8")
assert(bad_delimiter.key?("parser_err_msg"), "LEEF unsupported delimiter")

# Previously accepted malformed KV trailing strings must not silently vanish.
_, kv_bad = execute_parser(folder, "sample_kv", "src_ip=192.0.2.7 extra-word")
assert(kv_bad.key?("parser_err_msg"), "Strict KV trailing-garbage detection")

# Explicit no-multiline authoring: fail closed instead of classifying a
# malformed event with a dropped newline or an empty LEEF extension token.
malformed_single_event = [
  ["sample_cef", "CEF:0|Synthetic|FW|1|42|Denied|8|src=192.0.2.8 dpt=443 act=deny\n"],
  ["sample_leef", "LEEF:1.0|Synthetic|FW|1|5|src=192.0.2.8\tdstPort=443\tact=deny\n"],
  ["sample_csv", "192.0.2.8,443,deny\r\n"],
  ["sample_leef", "LEEF:2.0|Synthetic|FW|1|6|^|src=192.0.2.8^^dstPort=443^act=deny"]
]
malformed_single_event.each do |slug, raw|
  _, rejected = execute_parser(folder, slug, raw)
  assert(rejected['parser_err_msg'] == 'ArgumentError', "#{slug}: malformed event must be rejected")
  assert(rejected['parser_err_stage'] == 'extraction', "#{slug}: extraction-stage error required")
  assert(!rejected.key?('srcip'), "#{slug}: malformed event cannot yield partial fields")
end

# RFC5424 permits multiple adjacent SD-ELEMENTs and escaped ']' inside
# quoted parameter values. Preserve parsed SD for a future explicit mapping.
sd_multi = '<165>1 2026-10-12T01:02:03Z edge01 firewall 123 ID42 [origin@32473 name="first"][trace@32473 id="2"] src_ip=198.51.100.5 action=deny'
_, multi = execute_parser(folder, "sample_syslog", sd_multi)
assert(multi['srcip'] == '198.51.100.5', "RFC5424 multiple SD elements")
assert(multi['stellar_log_index'] == 'threat', "RFC5424 multiple SD routing")
sd_parser_path = File.join(folder, 'customized_sample_syslog')
sd_parser_class = Class.new
sd_parser_class.class_eval(SyntheticFixtureGuard.read_source(sd_parser_path), sd_parser_path, 1)
sd_instance = sd_parser_class.new
assert(sd_instance.parserstudio_extract(sd_multi)['syslog_structured_data'] ==
  '[origin@32473 name="first"][trace@32473 id="2"]', "RFC5424 adjacent blocks retained")
sd_escaped = '<165>1 2026-10-12T01:02:03Z edge01 firewall 123 ID42 [origin@32473 note="a\\]b"] src_ip=198.51.100.6 action=allow'
_, sd_ok = execute_parser(folder, "sample_syslog", sd_escaped)
assert(sd_ok['srcip'] == '198.51.100.6', "RFC5424 escaped SD bracket")
assert(sd_instance.parserstudio_extract(sd_escaped)['syslog_structured_data'] ==
  '[origin@32473 note="a\]b"]', "RFC5424 quoted SD bracket escape retained")
sd_bad = '<165>1 2026-10-12T01:02:03Z edge01 firewall 123 ID42 [origin@32473 note="unterminated] src_ip=198.51.100.6 action=deny'
_, invalid_sd = execute_parser(folder, "sample_syslog", sd_bad)
assert(invalid_sd['parser_err_stage'] == 'extraction', "RFC5424 unterminated quoted SD rejected")
sd_junk = '<165>1 2026-10-12T01:02:03Z edge01 firewall 123 ID42 [origin@32473]junk src_ip=198.51.100.6 action=deny'
_, invalid_junk = execute_parser(folder, "sample_syslog", sd_junk)
assert(invalid_junk['parser_err_stage'] == 'extraction', "RFC5424 trailing junk rejected")

# RFC5424 envelopes containing explicitly selected standalone CEF/LEEF bodies.
syslog_cef = '<165>1 2026-10-12T01:02:03Z edge fw 1 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny'
time_cef, parsed_cef = execute_parser(folder, "sample_syslog_cef", syslog_cef)
assert(parsed_cef['srcip'] == '192.0.2.11' && parsed_cef['dstport'] == 443, "RFC5424 nested CEF typed mapping")
assert(parsed_cef['stellar_log_index'] == 'threat', "RFC5424 nested CEF classification")
assert(time_cef.utc.iso8601 == "2026-10-12T01:02:03Z", "RFC5424 nested CEF event time")
syslog_leef = '<165>1 2026-10-12T01:02:03Z edge fw 1 ID - LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow'
time_leef, parsed_leef = execute_parser(folder, "sample_syslog_leef", syslog_leef)
assert(parsed_leef['srcip'] == '203.0.113.8' && parsed_leef['dstport'] == 80, "RFC5424 nested LEEF typed mapping")
assert(parsed_leef['stellar_log_index'] == 'session', "RFC5424 nested LEEF classification")
assert(time_leef.utc.iso8601 == "2026-10-12T01:02:03Z", "RFC5424 nested LEEF event time")
_, bad_nested_cef = execute_parser(folder, "sample_syslog_cef",
  '<165>1 2026-10-12T01:02:03Z edge fw 1 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 extra')
assert(bad_nested_cef['parser_err_stage'] == 'extraction' && !bad_nested_cef.key?('srcip'), "Malformed nested CEF fails closed")
_, bad_nested_leef = execute_parser(folder, "sample_syslog_leef",
  '<165>1 2026-10-12T01:02:03Z edge fw 1 ID - LEEF:2.0|Synthetic|FW|1|501|::|src=203.0.113.8')
assert(bad_nested_leef['parser_err_stage'] == 'extraction' && !bad_nested_leef.key?('srcip'), "Malformed nested LEEF fails closed")
# Explicit LEEF 2.0 0xHH delimiter subset. The hexadecimal representation
# is part of the LEEF header, not an instruction to execute arbitrary data.
leef_hex_caret = 'LEEF:2.0|Synthetic|FW|1|501|0x5E|src=203.0.113.22^dstPort=443^act=deny'
_, hex_caret = execute_parser(folder, "sample_leef", leef_hex_caret)
assert(hex_caret['srcip'] == '203.0.113.22' &&
       hex_caret['dstport'] == 443 &&
       hex_caret['stellar_log_index'] == 'threat', "LEEF 2.0 0x5E extension")
leef_hex_pipe = 'LEEF:2.0|Synthetic|FW|1|501|0x7C|src=203.0.113.23|dstPort=80|act=allow'
_, hex_pipe = execute_parser(folder, "sample_leef", leef_hex_pipe)
assert(hex_pipe['srcip'] == '203.0.113.23' &&
       hex_pipe['stellar_log_index'] == 'session', "LEEF 2.0 0x7C extension")
["0x0A", "0x00", "0x3D", "0xGG"].each do |hex|
  bad_hex = "LEEF:2.0|Synthetic|FW|1|501|#{hex}|src=203.0.113.25^dstPort=80^act=deny"
  _, rejected = execute_parser(folder, "sample_leef", bad_hex)
  assert(rejected['parser_err_stage'] == 'extraction' &&
         !rejected.key?('srcip'), "Unsupported LEEF separator #{hex} must reject")
end
_, nested_hex = execute_parser(folder, "sample_syslog_leef",
  '<165>1 2026-10-12T01:02:03Z edge fw 1 ID - LEEF:2.0|Synthetic|FW|1|501|0x7C|src=203.0.113.24|dstPort=80|act=allow')
assert(nested_hex['srcip'] == '203.0.113.24' &&
       nested_hex['stellar_log_index'] == 'session', "RFC5424 nested LEEF hex separator")
# Reject unsupported event version and malformed timestamp before mapping.
# These invoke the extractor directly, so rejection cannot accidentally be
# attributed to an optional normalization mapping or a downstream coercion.
cef_parser_path = File.join(folder, 'customized_sample_cef')
cef_class = Class.new
cef_class.class_eval(SyntheticFixtureGuard.read_source(cef_parser_path), cef_parser_path, 1)
cef_instance = cef_class.new
unsupported_cef = 'CEF:9|Synthetic|FW|1|42|Blocked|8|src=192.0.2.7 dpt=443 act=deny'
begin
  cef_instance.parserstudio_extract(unsupported_cef)
  raise 'Unknown CEF version silently accepted'
rescue ArgumentError
  # expected
end
invalid_syslog_timestamps = [
  'not-a-timestamp',
  '2026-99-99T25:01:01Z',
  '2026-10-12T01:02:03',
]
invalid_syslog_timestamps.each do |stamp|
  record = "<165>1 #{stamp} edge fw 1 ID - src_ip=192.0.2.11 action=deny"
  begin
    sd_instance.parserstudio_extract(record)
    raise "Malformed RFC5424 timestamp silently accepted"
  rescue ArgumentError
    # expected extraction stage, independent of field mapping
  end
end
nil_value = sd_instance.parserstudio_extract('<165>1 - edge fw 1 ID - src_ip=192.0.2.11 action=deny')
assert(nil_value['syslog_timestamp'] == '-', "RFC5424 timestamp NILVALUE preserved")
# Strict RFC5424 header subset: version 1 and bounded, printable ASCII
# HOSTNAME/APP-NAME/PROCID/MSGID. No silent version upgrades or controls.
rfc5424_head = '<165>1 2026-10-12T01:02:03Z edge fw 123 ID - src_ip=192.0.2.11 action=deny'
head_ok = sd_instance.parserstudio_extract(rfc5424_head)
assert(head_ok['syslog_version'] == 1, "RFC5424 valid v1")
header_cases = [
  ['version-two', '<165>2 2026-10-12T01:02:03Z edge fw 123 ID - src_ip=192.0.2.11 action=deny'],
  ['hostname-size', "<165>1 2026-10-12T01:02:03Z #{'h' * 256} fw 123 ID - src_ip=192.0.2.11 action=deny"],
  ['appname-size', "<165>1 2026-10-12T01:02:03Z edge #{'a' * 49} 123 ID - src_ip=192.0.2.11 action=deny"],
  ['procid-size', "<165>1 2026-10-12T01:02:03Z edge fw #{'p' * 129} ID - src_ip=192.0.2.11 action=deny"],
  ['msgid-size', "<165>1 2026-10-12T01:02:03Z edge fw 123 #{'i' * 33} - src_ip=192.0.2.11 action=deny"],
  ['hostname-non-ascii', '<165>1 2026-10-12T01:02:03Z 테스트 fw 123 ID - src_ip=192.0.2.11 action=deny'],
  ['hostname-nul', "<165>1 2026-10-12T01:02:03Z e\x00dge fw 123 ID - src_ip=192.0.2.11 action=deny"],
]
header_cases.each do |id, text|
  begin
    sd_instance.parserstudio_extract(text)
    raise "RFC5424 invalid header #{id} silently accepted"
  rescue ArgumentError
    # Fail closed before field normalization, never emit partial data.
  end
end
max_hostname = '<165>1 2026-10-12T01:02:03Z ' + ('h' * 255) + ' fw 123 ID - src_ip=192.0.2.11 action=deny'
assert(sd_instance.parserstudio_extract(max_hostname)['body']['src_ip'] == '192.0.2.11',
       "RFC5424 maximum reviewed hostname length")
puts "Extended synthetic formats: 45 scenarios PASS (CSV/RFC5424/CEF/LEEF)"

# Escaped CEF/LEEF header delimiters must not accept an incomplete escape.
# A dangling backslash is not evidence of a complete parsed event.
delimiter_parser_path = File.join(folder, 'customized_sample_cef')
delimiter_parser_class = Class.new
delimiter_parser_class.class_eval(SyntheticFixtureGuard.read_source(delimiter_parser_path), delimiter_parser_path, 1)
delimiter_parser = delimiter_parser_class.new
begin
  delimiter_parser.parserstudio_split_escaped("first|second\\", '|', 1)
  raise "Incomplete CEF header escape silently accepted"
rescue ArgumentError
  # Expected a static extraction error.
end
_, leef_dangling = execute_parser(folder, 'sample_leef', "LEEF:1.0|Synthetic|FW|1|500|src=203.0.113.7\\")
assert(leef_dangling['parser_err_msg'] == 'ArgumentError' &&
       leef_dangling['parser_err_stage'] == 'extraction' &&
       !leef_dangling.key?('srcip'), 'LEEF dangling header escape must fail closed')
puts "Delimited header escape safety: 2 malformed cases REJECTED (synthetic only)"
