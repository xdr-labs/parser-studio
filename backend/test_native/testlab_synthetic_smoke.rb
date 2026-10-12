# Fixed public-synthetic JSON/KV/CSV/CEF/LEEF preview through pinned Fluentd Parser API.
# No live sensor, customer logs, network transport, or runtime target import.
require 'json'
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'
require_relative 'synthetic_fixture_guard'

def verified(condition, code)
  raise "Synthetic Test Lab native callback failed: #{code}" unless condition
end

directory=File.expand_path(ARGV.fetch(0))
verified(directory==File.expand_path('../.tmp/native-fixtures',__dir__), 'DIRECTORY')
input=STDIN.read(65536)
verified(input.bytesize>0 && input.bytesize<65536, 'SIZE')
events=JSON.parse(input)
verified(events.keys.sort==%w[cef csv json kv leef leef1], 'CONTRACT')
Fluent::Test.setup
events.each do |format, preview|
  verified(preview['safeToSendToSensor']==false &&
    preview['runtimeParsingVerified']==false &&
    preview['targetSensorVerified']==false, 'READINESS')
  verified(preview['generatedAt']=='2026-10-12T01:02:03.000Z','CLOCK')
  verified(preview['syntheticEvent'].is_a?(String) &&
    preview['syntheticEvent'].bytesize<=16384,'BOUNDS')
  slug={'json'=>'sample_firewall','kv'=>'sample_kv','csv'=>'sample_csv',
    'cef'=>'sample_cef','leef'=>'sample_leef','leef1'=>'sample_leef'}[format]
  verified(!slug.nil?, 'FORMAT')
  file=File.join(directory,"customized_#{slug}")
  klass=Class.new(Fluent::Plugin::Parser)
  klass.class_eval(SyntheticFixtureGuard.read_source(file),file,1)
  driver=Fluent::Test::Driver::Parser.new(klass).configure('')
  results=[]
  driver.instance.parse(preview['syntheticEvent']) do |event_time,record|
    results << [event_time,record]
  end
  verified(results.length==1,'CALLBACK_COUNT')
  _,record=results.first
  verified(record.is_a?(Hash) && record['parser_err_msg'].nil?,'NO_PARSER_ERRORS')
  verified(record['stellar_log_index']=='threat','CLASSIFICATION')
  verified(record['srcip'].is_a?(String) &&
    record['srcip'].match?(/\A(?:192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])\z/),
    'DOCUMENTATION_IP')
  verified(record['action']=='deny','ACTION_PRESERVED')
end
puts 'Synthetic Test Lab JSON/KV/CSV/CEF/LEEF event previews: 6 Fluentd native callbacks PASS, sent=0'
