# Tests allowlisted normalization enrichments on the generated Ruby fragment.
# The test is synthetic, not a Stellar Cyber upload/installation test.
require 'json'

def check(condition, message)
  raise "FAILED: #{message}" unless condition
end

folder = ARGV.fetch(0)
file = File.join(folder, 'customized_sample_enriched')
generated = Class.new
generated.class_eval(File.read(file), file, 1)
parser = generated.new

input = JSON.generate({
  'source' => {'ip' => '192.0.2.15'},
  'destination' => {'ip' => '198.51.100.55', 'port' => 443},
  'action' => 'DeNy',
  'event' => {'id' => '789'}
})
result = nil
parser.parse(input) { |_time, record| result = record }
check(result.dig('log', 'source_label') == 'synthetic', 'constant label')
check(result.dig('log', 'action_lower') == 'deny', 'lowercase')
check(result.dig('log', 'action_upper') == 'DENY', 'uppercase based on earlier enrichment')
check(result.dig('log', 'original_srcip') == '192.0.2.15', 'safe copy')
check(result['stellar_log_index'] == 'threat', 'classify from enrichment result')
check(result['parser_err_msg'].nil?, 'no false diagnostic')
puts 'Ruby enrichment: constant/copy/lower/upper/classification PASS (synthetic only)'
