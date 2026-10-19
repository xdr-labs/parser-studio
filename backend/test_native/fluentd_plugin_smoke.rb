# Test-generated parser fragment attached to Fluentd 1.17.1's actual Parser Plugin
# and executed through Fluent::Test::Driver::Parser, in an isolated local
# development directory with synthetic fixtures. Never connect to rickmodular.
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'
require 'json'
require_relative 'synthetic_fixture_guard'

def assert(condition, detail)
  raise "FAIL: #{detail}" unless condition
end

def driver_for(directory, slug)
  file = File.join(directory, "customized_#{slug}")
  source = SyntheticFixtureGuard.read_source(file)
  subclass = Class.new(Fluent::Plugin::Parser)
  subclass.class_eval(source, file, 1)
  Fluent::Plugin.register_parser("customized_#{slug}", subclass)
  Fluent::Test::Driver::Parser.new(subclass).configure('')
end

def parse_once(driver, raw)
  results = []
  driver.instance.parse(raw) do |time, record|
    results << [time, record]
  end
  assert(results.length == 1, "Fluentd callback count #{results.length}")
  results.first
end

directory = ARGV.fetch(0)
Fluent::Test.setup
names = %w[sample_firewall sample_kv sample_extended sample_csv sample_syslog sample_syslog_cef sample_syslog_leef sample_cef sample_leef sample_enriched]
drivers = {}
names.each do |slug|
  drivers[slug] = driver_for(directory, slug)
end

event = JSON.generate({
  'source' => {'ip' => '192.0.2.10'},
  'destination' => {'ip' => '198.51.100.25', 'port' => '443'},
  'action' => 'deny', 'event' => {'id' => '99'}
})
time, record = parse_once(drivers['sample_firewall'], event)
assert(record['stellar_log_index'] == 'threat', 'native JSON threat category')
assert(record['srcip'] == '192.0.2.10', 'native JSON IP mapping')
assert(record['dstport'] == 443, 'native integer port')
assert(record.dig('log', 'event_id') == 99, 'native nested mapping')

_, kv = parse_once(drivers['sample_kv'], 'src_ip=192.0.2.4 dst_port=53 action=deny')
assert(kv['stellar_log_index'] == 'threat', 'native KV classification')

_, csv = parse_once(drivers['sample_csv'], '192.0.2.5,443,"deny"')
assert(csv['dstport'] == 443, 'native CSV field')

syslog = "<34>1 2026-10-12T02:03:04Z edge fw 122 CONNECT - src_ip=198.51.100.14 action=deny"
syslog_time, parsed = parse_once(drivers['sample_syslog'], syslog)
assert(parsed['srcip'] == '198.51.100.14', 'native syslog structured body')
assert(syslog_time && syslog_time.utc.strftime('%Y-%m-%dT%H:%M:%SZ') == '2026-10-12T02:03:04Z', 'native syslog event time')
sd_native = '<165>1 2026-10-12T02:03:04Z edge fw 122 CONNECT [meta@32473 note="alpha"][trace@32473 id="1"] src_ip=198.51.100.14 action=deny'
_, valid_sd = parse_once(drivers['sample_syslog'], sd_native)
assert(valid_sd['srcip'] == '198.51.100.14' &&
       valid_sd['stellar_log_index'] == 'threat', 'native RFC5424 adjacent SD grammar')
bad_sd_native = '<165>1 2026-10-12T02:03:04Z edge fw 122 CONNECT [meta@32473 note=invalid] src_ip=198.51.100.14 action=deny'
_, invalid_sd = parse_once(drivers['sample_syslog'], bad_sd_native)
assert(invalid_sd['parser_err_msg'] == 'ArgumentError' &&
       invalid_sd['parser_err_stage'] == 'extraction' &&
       !invalid_sd.key?('srcip'), 'native RFC5424 invalid parameter fails closed')
bad_time = '<165>1 invalid-timestamp edge fw 122 ID - src_ip=192.0.2.10 action=deny'
_, invalid_time = parse_once(drivers['sample_syslog'], bad_time)
assert(invalid_time['parser_err_stage'] == 'extraction', 'native RFC5424 invalid timestamp rejected')
unknown_version = '<165>2 2026-10-12T01:02:03Z edge fw 122 ID - src_ip=192.0.2.5 action=deny'
_, invalid_version = parse_once(drivers['sample_syslog'], unknown_version)
assert(invalid_version['parser_err_stage'] == 'extraction' &&
       !invalid_version.key?('srcip'), 'native RFC5424 v2 fail closed')
_, invalid_cef_version = parse_once(drivers['sample_cef'],
  'CEF:9|Synthetic|FW|1|42|Blocked|8|src=192.0.2.10 dpt=443 act=deny')
assert(invalid_cef_version['parser_err_stage'] == 'extraction', 'native CEF unsupported version rejected')

syslog_cef = '<165>1 2026-10-12T02:03:04Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny'
_, cef_enveloped = parse_once(drivers['sample_syslog_cef'], syslog_cef)
assert(cef_enveloped['srcip'] == '192.0.2.11' &&
       cef_enveloped['stellar_log_index'] == 'threat', 'native RFC5424 CEF body classification')
syslog_leef = '<165>1 2026-10-12T02:03:04Z edge fw 122 ID - LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow'
_, leef_enveloped = parse_once(drivers['sample_syslog_leef'], syslog_leef)
assert(leef_enveloped['srcip'] == '203.0.113.8' &&
       leef_enveloped['stellar_log_index'] == 'session', 'native RFC5424 LEEF body classification')


_, cef = parse_once(drivers['sample_cef'], 'CEF:0|Acme|FW|1|100|Blocked|8|src=192.0.2.11 dst=198.51.100.22 dpt=443 act=deny')
assert(cef['dstip'] == '198.51.100.22', 'native CEF extension')

_, leef = parse_once(drivers['sample_leef'], "LEEF:1.0|Acme|FW|1|7|src=203.0.113.5\tdstPort=80\tact=deny")
assert(leef['srcip'] == '203.0.113.5', 'native LEEF')
_, hex_leef = parse_once(drivers['sample_leef'],
  'LEEF:2.0|Synthetic|FW|1|501|0x7C|src=203.0.113.23|dstPort=80|act=allow')
assert(hex_leef['srcip'] == '203.0.113.23' &&
       hex_leef['stellar_log_index'] == 'session', 'native LEEF hex delimiter')
_, nested_hex = parse_once(drivers['sample_syslog_leef'],
  '<165>1 2026-10-12T02:03:04Z edge fw 122 ID - LEEF:2.0|Synthetic|FW|1|501|0x7C|src=203.0.113.24|dstPort=80|act=allow')
assert(nested_hex['srcip'] == '203.0.113.24', 'native nested LEEF hex delimiter')

_, enriched = parse_once(drivers['sample_enriched'], JSON.generate({
  'source' => {'ip' => '192.0.2.17'},
  'destination' => {'ip' => '198.51.100.77', 'port' => '443'},
  'action' => 'DENY', 'endpoint' => '192.0.2.17:443', 'event' => {'id' => '7'}
}))
assert(enriched.dig('log', 'action_lower') == 'deny', 'native enrichment')
assert(enriched.dig('log', 'endpoint_host') == '192.0.2.17' &&
       enriched.dig('log', 'endpoint_port') == '443' &&
       enriched.dig('log', 'endpoint_joined') == '192.0.2.17:443', 'native split and merge enrichment')
assert(enriched['stellar_log_index'] == 'threat', 'native enriched classification')

_, bad = parse_once(drivers['sample_cef'], 'CEF:0|Acme|FW|1|100|Blocked|8|garbage')
assert(bad.key?('parser_err_msg'), 'native malformed CEF rejected')

assert(Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1', 'runtime version pinned')
puts 'Fluentd 1.17.1 Parser Plugin API: 10 profiles + failure path PASS (synthetic only)'
