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

puts "Extended synthetic formats: 16 scenarios PASS (CSV/RFC5424/CEF/LEEF)"
