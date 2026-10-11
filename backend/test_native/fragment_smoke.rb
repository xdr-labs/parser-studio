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

puts 'Ruby fragment synthetic callback tests: 5 cases PASS (not Fluentd/target import)'
