# Pinned offline Fluentd Parser Plugin API golden regression.
# Only reviewer-authored public synthetic inputs from this repository.
# The source files are emitted by the reviewed fixed compiler template;
# this script never loads user-supplied or live vendor Ruby/CONF/logs.
require 'json'
require 'digest'
require 'securerandom'
require 'time'
require_relative 'synthetic_fixture_guard'
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'

def assert(condition, message)
  raise "Synthetic golden fixture validation failed: #{message}" unless condition
end

expected_directory = File.expand_path('../.tmp/native-fixtures', __dir__)
expected_fixture = File.expand_path('fixtures/synthetic-golden.v0.1.json', __dir__)
arg_directory = File.expand_path(ARGV.fetch(0))
arg_fixture = File.expand_path(ARGV.fetch(1))
assert(arg_directory == expected_directory && arg_fixture == expected_fixture,
  'Synthetic native fixture boundary requires the fixed generated directory and reviewed golden source')
directory = File.realpath(arg_directory)
fixture_file = File.realpath(arg_fixture)
assert(directory == expected_directory && fixture_file == expected_fixture,
  'Synthetic native fixture boundary rejects symlink redirection')
assert(!File.lstat(expected_directory).symlink? && !File.lstat(expected_fixture).symlink?,
  'Synthetic native fixture boundary rejects symlinks')
fixture = JSON.parse(File.binread(fixture_file))
assert(fixture['kind'] == 'parser-studio.synthetic-golden-events.v0.1', 'contract kind')
assert(fixture['origin'] == 'independently-authored-public-synthetic', 'fixture provenance')
assert(fixture['cases'].is_a?(Array) && fixture['cases'].length == 23, 'expected ten events')

allowed_profiles = %w[
  sample_firewall sample_kv sample_extended sample_csv sample_syslog
  sample_syslog_cef sample_syslog_leef sample_cef sample_leef sample_enriched
]
assert(fixture['cases'].map { |item| item['slug'] }.uniq.sort == allowed_profiles.sort, 'ten profiles')

Fluent::Test.setup
drivers = {}
allowed_profiles.each do |slug|
  path = File.join(directory, "customized_#{slug}")
  assert(File.file?(path), "generated fixture missing: #{slug}")
  stat = File.lstat(path)
  assert(stat.file? && !stat.symlink? && stat.nlink == 1,
    "Synthetic native fixture boundary rejects unsafe generated source files")
  parser_class = Class.new(Fluent::Plugin::Parser)
  parser_class.class_eval(SyntheticFixtureGuard.read_source(path), path, 1)
  Fluent::Plugin.register_parser("customized_#{slug}", parser_class)
  drivers[slug] = Fluent::Test::Driver::Parser.new(parser_class).configure('')
end

# Canonical values here belong ONLY to the fixed, public synthetic suite.
# Persist their SHA-256, never source events or normalized field values.
def canonical_native_value(value)
  case value
  when Hash
    value.keys.sort.each_with_object({}) do |key, ordered|
      ordered[key] = canonical_native_value(value.fetch(key))
    end
  when Array
    value.map { |item| canonical_native_value(item) }
  else
    value
  end
end

case_rows = []
fixture['cases'].each do |entry|
  assert(entry['id'].is_a?(String) && entry['id'].match?(/\A[a-z][a-z0-9_-]+\z/), 'fixture ID')
  assert(allowed_profiles.include?(entry['slug']), "unsupported profile #{entry['id']}")
  assert(entry['raw'].is_a?(String) && entry['raw'].bytesize <= 16384, "input bound #{entry['id']}")
  assert(entry['expectedRecord'].is_a?(Hash), "expected record #{entry['id']}")
  status = 'CALLBACK_COUNT'
  output_sha = nil
  begin
    emitted = []
    drivers.fetch(entry['slug']).instance.parse(entry['raw']) do |time, record|
      emitted << [time, record]
    end
    if emitted.length == 1
      actual_time, actual_record = emitted.fetch(0)
      time_iso = if actual_time.nil?
        nil
      elsif actual_time.respond_to?(:to_time)
        actual_time.to_time.utc.iso8601
      else
        Time.at(actual_time.to_r).utc.iso8601
      end
      output_sha = Digest::SHA256.hexdigest(
        JSON.generate([time_iso, canonical_native_value(actual_record)]))
      status = if time_iso != entry['expectedTime']
        'TIME_MISMATCH'
      elsif actual_record != entry['expectedRecord']
        'RECORD_MISMATCH'
      else
        'PASS'
      end
    end
  rescue StandardError
    status = 'PARSER_EXCEPTION'
    output_sha = nil
  end
  case_rows << {
    id: entry['id'], slug: entry['slug'], status: status, outputSha256: output_sha
  }
end

# Atomic private file replacement; a malicious or interrupted previous output
# cannot redirect this report to an unrelated path.
case_report = {
  kind: 'parser-studio.synthetic-native-case-evidence.v0.1',
  origin: fixture['origin'],
  backendHead: IO.popen(['git', 'rev-parse', 'HEAD'], &:read).strip,
  fixtureSha256: Digest::SHA256.file(fixture_file).hexdigest,
  ruby: '3.2', fluentd: '1.17.1', cases: case_rows,
  sensorTrafficSent: false, actualTdAgentOrStellarImport: false,
  targetImportVerified: false
}
destination = '.tmp/synthetic-golden-cases-report.json'
stage = ".tmp/.golden-cases-#{SecureRandom.hex(12)}.tmp"
begin
  File.open(stage, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |f|
    f.write(JSON.generate(case_report) + "\n")
    f.flush
    f.fsync
  end
  File.rename(stage, destination)
  File.open('.tmp', File::RDONLY) { |directory| directory.fsync }
ensure
  File.unlink(stage) if File.exist?(stage)
end
bad = case_rows.count { |entry| entry[:status] != 'PASS' }
assert(bad == 0, "native synthetic golden case regression (#{bad} failing cases; redacted evidence stored)")

assert(Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1', 'native runtime is not the pinned Fluentd version')
report = {
  kind: 'parser-studio.synthetic-golden-native.v0.1',
  backendHead: IO.popen(['git', 'rev-parse', 'HEAD'], &:read).strip,
  origin: fixture['origin'],
  fixtureSha256: Digest::SHA256.file(fixture_file).hexdigest,
  casesPassed: fixture['cases'].length,
  profilesPassed: allowed_profiles.length,
  fluentd: '1.17.1',
  actualTdAgentOrStellarImport: false,
  targetImportVerified: false
}
File.open('.tmp/synthetic-golden-report.json', File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |f|
  f.write(JSON.pretty_generate(report) + "\n")
end
puts "Pinned Fluentd Parser API golden events: #{report[:casesPassed]} exact records in #{report[:profilesPassed]} profiles PASS (synthetic only)"
