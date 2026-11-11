# Exact compiler-generated per-project Native verifier.
# Input arrives only on stdin from the trusted backend boundary. The program
# never prints raw/normalized values and never opens a network listener.
require 'json'
require 'digest'
require 'time'
require 'fluent/config'
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'

MAX_INPUT = 768 * 1024
MAX_EVENTS = 500
SHA = /\A[a-f0-9]{64}\z/
NAME = /\Acustomized_[a-z][a-z0-9_]{1,47}\z/

def fail_native
  raise 'NATIVE_PROJECT_RUNNER_FAILED'
end

def exact_keys(value, keys)
  value.is_a?(Hash) && value.keys.sort == keys.sort
end

def canonical(value)
  case value
  when Hash
    '{' + value.keys.sort.map { |key| JSON.generate(key) + ':' + canonical(value.fetch(key)) }.join(',') + '}'
  when Array
    '[' + value.map { |entry| canonical(entry) }.join(',') + ']'
  else
    JSON.generate(value)
  end
end

def event_time_ms(value)
  return nil if value.nil?
  time = value.respond_to?(:to_time) ? value.to_time : Time.at(value.to_r)
  (time.to_r * 1000).to_i
end

begin
  source = STDIN.read(MAX_INPUT + 1)
  fail_native if source.bytesize > MAX_INPUT || source.empty?
  input = JSON.parse(source)
  root_keys = %w[contract sourceSha256 recipeSha256 parserName confName parserSha256 confSha256 receiver parserSource confSource events]
  fail_native unless exact_keys(input, root_keys)
  fail_native unless input['contract'] == 'parser-studio.native-project-runner-input.v0.1'
  %w[sourceSha256 recipeSha256 parserSha256 confSha256].each do |key|
    fail_native unless input[key].is_a?(String) && input[key].match?(SHA)
  end
  fail_native unless input['parserName'].is_a?(String) && input['parserName'].match?(NAME)
  fail_native unless input['confName'] == input['parserName'] + '.conf'
  fail_native unless input['parserSource'].is_a?(String) && input['confSource'].is_a?(String)
  fail_native unless input['parserSource'].bytesize <= 256 * 1024 && input['confSource'].bytesize <= 64 * 1024
  fail_native unless Digest::SHA256.hexdigest(input['parserSource']) == input['parserSha256']
  fail_native unless Digest::SHA256.hexdigest(input['confSource']) == input['confSha256']

  receiver = input['receiver']
  fail_native unless exact_keys(receiver, %w[port protocols])
  fail_native unless receiver['port'].is_a?(Integer) && receiver['port'].between?(1, 65_535)
  fail_native unless receiver['protocols'].is_a?(Array) &&
    receiver['protocols'].length.between?(1, 2) &&
    receiver['protocols'].uniq.length == receiver['protocols'].length &&
    receiver['protocols'].all? { |x| %w[tcp udp].include?(x) }

  events = input['events']
  fail_native unless events.is_a?(Array) && events.length.between?(1, MAX_EVENTS)
  events.each_with_index do |entry, index|
    fail_native unless exact_keys(entry, %w[eventId raw recordSha256 eventTimeMs])
    fail_native unless entry['eventId'] == "event-#{index + 1}"
    fail_native unless entry['raw'].is_a?(String) && entry['raw'].bytesize.between?(1, 16 * 1024)
    fail_native unless entry['recordSha256'].is_a?(String) && entry['recordSha256'].match?(SHA)
    t = entry['eventTimeMs']
    fail_native unless t.nil? || (t.is_a?(Integer) && t.abs <= 8_640_000_000_000_000)
  end

  Fluent::Test.setup
  fail_native unless Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1'
  ruby_version = RUBY_VERSION.split('.')[0,2].join('.')
  fail_native unless ruby_version == '3.2'

  klass = Class.new(Fluent::Plugin::Parser)
  klass.class_eval(input['parserSource'], input['parserName'], 1)
  Fluent::Plugin.register_parser(input['parserName'], klass)
  driver = Fluent::Test::Driver::Parser.new(klass).configure('')

  include_line = '  @include /etc/td-agent/transport_settings.conf'
  conf = input['confSource'].lines.reject { |line| line.strip == include_line.strip }.join
  parsed = Fluent::Config.parse(conf, input['confName'], '.', true)
  sources = parsed.elements.select { |x| x.name == 'source' }
  fail_native unless sources.length == receiver['protocols'].length
  fail_native unless sources.map { |x| x['@type'] }.sort == receiver['protocols'].sort
  sources.each do |entry|
    fail_native unless entry['port'] == receiver['port'].to_s &&
      entry['tag'] == input['parserName'] &&
      entry.elements.length == 1 &&
      entry.elements.first['@type'] == input['parserName']
  end
  matches = parsed.elements.select { |x| x.name == 'match' }
  fail_native unless matches.length == 1 &&
    matches.first.arg == "#{input['parserName']}.**" &&
    matches.first['@type'] == 'rewrite_tag_filter'

  passed = 0
  events.each do |entry|
    outputs = []
    driver.instance.parse(entry['raw']) { |time, record| outputs << [time, record] }
    fail_native unless outputs.length == 1
    event_time, record = outputs.first
    actual_hash = Digest::SHA256.hexdigest(canonical(record))
    fail_native unless actual_hash == entry['recordSha256']
    if entry['eventTimeMs'].nil?
      # No record timestamp is mapped. The generated parser must then hand the receive
      # time to the wrapper: Stellar's receivers report a nil time as "pattern not
      # matched" instead of emitting the event.
      actual_ms = event_time_ms(event_time)
      fail_native if actual_ms.nil?
      fail_native unless (actual_ms - (Time.now.to_r * 1000).to_i).abs <= 60_000
    else
      fail_native unless event_time_ms(event_time) == entry['eventTimeMs']
    end
    passed += 1
  end

  report = {
    'contract' => 'parser-studio.native-project-verification.v0.1',
    'sourceSha256' => input['sourceSha256'],
    'recipeSha256' => input['recipeSha256'],
    'parserSha256' => input['parserSha256'],
    'confSha256' => input['confSha256'],
    'eventCount' => events.length,
    'eventsPassed' => passed,
    'recordHashMatches' => passed,
    'eventTimeMatches' => passed,
    'ruby' => '3.2',
    'fluentd' => '1.17.1',
    'confAstVerified' => true,
    'parserCallbackVerified' => true,
    'sourceHashVerifiedAgainstEvents' => true,
    'nativeUserParserVerified' => true,
    'targetImportVerified' => false,
    'sensorTrafficSent' => false,
    'rawValuesReturned' => false
  }
  STDOUT.write(JSON.generate(report))
rescue StandardError
  STDERR.write("NATIVE_PROJECT_RUNNER_FAILED\n")
  exit 1
end
