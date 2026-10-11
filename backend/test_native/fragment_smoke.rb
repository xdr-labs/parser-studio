# Synthetic input only. Tests the generated Ruby callback; no Fluentd or
# proprietary Stellar target import is exercised by this test.
require 'json'

def assert(value, message)
  raise "FAIL: #{message}" unless value
end

def parse_once(file, text)
  klass = Class.new
  klass.class_eval(File.read(file), file, 1)
  parser = klass.new
  result = nil
  invoked = 0
  parser.parse(text) do |time, record|
    invoked += 1
    result = record
  end
  assert(invoked == 1, 'parse must yield exactly one record')
  result
end

root = ARGV.fetch(0)
json_path = File.join(root, 'customized_sample_firewall')
kv_path = File.join(root, 'customized_sample_kv')

denied = JSON.generate({
  'source' => {'ip' => '192.0.2.18'},
  'destination' => {'ip' => '198.51.100.7', 'port' => '443'},
  'action' => 'deny', 'event' => {'id' => '101'}
})
threat = parse_once(json_path, denied)
assert(threat['srcip'] == '192.0.2.18', 'IPv4 src extraction')
assert(threat['dstip'] == '198.51.100.7', 'IPv4 dst extraction')
assert(threat['dstport'] == 443, 'port coercion')
assert(threat.dig('log','event_id') == 101, 'nested namespace mapping')
assert(threat['stellar_log_index'] == 'threat', 'threat classification')
assert(threat.dig('msg_origin','source') == 'sample_firewall', 'msg origin')

allowed = JSON.generate({
  'source' => {'ip' => '203.0.113.99'},
  'destination' => {'ip' => '198.51.100.7', 'port' => '53'},
  'action' => 'allow', 'event' => {'id' => '102'}
})
session = parse_once(json_path, allowed)
assert(session['stellar_log_index'] == 'session', 'session fallback')

unknown = parse_once(json_path, JSON.generate({'unmapped' => 'x'}))
assert(unknown['stellar_log_index'] == 'syslog', 'syslog default')

invalid = parse_once(json_path, '{invalid')
assert(invalid['parser_err_msg'] == 'JSON::ParserError', 'explain malformed JSON')
assert(invalid['stellar_log_index'] == 'syslog', 'errors route to syslog')

kv = parse_once(kv_path, 'src_ip=192.0.2.9 dst_port=80 action="deny"')
assert(kv['srcip'] == '192.0.2.9', 'KV src')
assert(kv['dstport'] == 80, 'KV port')
assert(kv['stellar_log_index'] == 'threat', 'KV threat')

bad_port = JSON.generate({
  'source' => {'ip' => '192.0.2.9'},
  'destination' => {'port' => '65536', 'ip' => '198.51.100.7'},
  'action' => 'deny'
})
invalid_port = parse_once(json_path, bad_port)
assert(invalid_port['parser_err_msg'] == 'MappedFieldError', 'invalid port rejected')
assert(invalid_port['parser_err_stage'] == 'normalization', 'normalization failure stage')
assert(invalid_port['parser_err_field'] == 'destination.port', 'exact invalid source field')

bad_ip = JSON.generate({
  'source' => {'ip' => '999.999.999.999'},
  'destination' => {'port' => '80', 'ip' => '198.51.100.7'},
  'action' => 'allow'
})
invalid_ip = parse_once(json_path, bad_ip)
assert(invalid_ip['parser_err_msg'] == 'MappedFieldError', 'invalid IP rejected')
assert(invalid_ip['parser_err_field'] == 'source.ip', 'invalid IP path identified')

extended = JSON.generate({
  'source' => {'ip' => '192.0.2.9'},
  'destination' => {'port' => '443', 'ip' => '198.51.100.7'},
  'action' => 'allow', 'event_time' => '2026-10-12T12:34:56Z', 'username' => 'synthetic-user'
})
extended_file = File.join(root, 'customized_sample_extended')
extended_record = nil
extended_time = nil
extended_class = Class.new
extended_class.class_eval(File.read(extended_file), extended_file, 1)
extended_class.new.parse(extended) do |event_time, record|
  extended_time = event_time
  extended_record = record
end
assert(extended_time.is_a?(Time), 'date event time')
assert(extended_time.utc.iso8601 == '2026-10-12T12:34:56Z', 'timezone UTC')
assert(extended_record.dig('Synthetic', 'username') == 'synthetic-user', 'vendor field mapping')

tzless = JSON.generate({
  'source' => {'ip' => '192.0.2.9'},
  'destination' => {'port' => '443', 'ip' => '198.51.100.7'},
  'action' => 'allow', 'event_time' => '2026-10-12T12:34:56'
})
_, tzless_record = nil, nil
tzless_record = parse_once(extended_file, tzless)
assert(tzless_record['parser_err_field'] == 'event_time', 'Unzoned timestamp cannot silently use local timezone')

puts 'Ruby fragment synthetic callback tests: 9 cases PASS (not Stellar target import)'
