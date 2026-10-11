# Test-generated parser fragment attached to Fluentd 1.17.1's actual Parser Plugin
# and executed through Fluent::Test::Driver::Parser, in an isolated local
# development directory with synthetic fixtures. Never connect to rickmodular.
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'
require 'json'

def assert(condition, detail)
  raise "FAIL: #{detail}" unless condition
end

def driver_for(directory, slug)
  file = File.join(directory, "customized_#{slug}")
  source = File.read(file)
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
names = %w[sample_firewall sample_kv sample_extended sample_csv sample_syslog sample_cef sample_leef sample_enriched]
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

_, cef = parse_once(drivers['sample_cef'], 'CEF:0|Acme|FW|1|100|Blocked|8|src=192.0.2.11 dst=198.51.100.22 dpt=443 act=deny')
assert(cef['dstip'] == '198.51.100.22', 'native CEF extension')

_, leef = parse_once(drivers['sample_leef'], "LEEF:1.0|Acme|FW|1|7|src=203.0.113.5\tdstPort=80\tact=deny")
assert(leef['srcip'] == '203.0.113.5', 'native LEEF')

_, enriched = parse_once(drivers['sample_enriched'], JSON.generate({
  'source' => {'ip' => '192.0.2.17'},
  'destination' => {'ip' => '198.51.100.77', 'port' => '443'},
  'action' => 'DENY', 'event' => {'id' => '7'}
}))
assert(enriched.dig('log', 'action_lower') == 'deny', 'native enrichment')
assert(enriched['stellar_log_index'] == 'threat', 'native enriched classification')

_, bad = parse_once(drivers['sample_cef'], 'CEF:0|Acme|FW|1|100|Blocked|8|garbage')
assert(bad.key?('parser_err_msg'), 'native malformed CEF rejected')

assert(Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1', 'runtime version pinned')
puts 'Fluentd 1.17.1 Parser Plugin API: 8 profiles + failure path PASS (synthetic only)'
