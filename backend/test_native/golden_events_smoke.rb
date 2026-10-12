# Pinned offline Fluentd Parser Plugin API golden regression.
# Only reviewer-authored public synthetic inputs from this repository.
# The source files are emitted by the reviewed fixed compiler template;
# this script never loads user-supplied or live vendor Ruby/CONF/logs.
require 'json'
require 'digest'
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
assert(fixture['cases'].is_a?(Array) && fixture['cases'].length == 22, 'expected ten events')

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

fixture['cases'].each do |entry|
  assert(entry['id'].is_a?(String) && entry['id'].match?(/\A[a-z][a-z0-9_-]+\z/), 'fixture ID')
  assert(allowed_profiles.include?(entry['slug']), "unsupported profile #{entry['id']}")
  assert(entry['raw'].is_a?(String) && entry['raw'].bytesize <= 16384, "input bound #{entry['id']}")
  assert(entry['expectedRecord'].is_a?(Hash), "expected record #{entry['id']}")
  emitted = []
  drivers.fetch(entry['slug']).instance.parse(entry['raw']) do |time, record|
    emitted << [time, record]
  end
  assert(emitted.length == 1, "unexpected callback count #{entry['id']}")
  actual_time, actual_record = emitted.fetch(0)
  time_iso = if actual_time.nil?
    nil
  elsif actual_time.respond_to?(:to_time)
    actual_time.to_time.utc.iso8601
  else
    Time.at(actual_time.to_r).utc.iso8601
  end
  assert(time_iso == entry['expectedTime'], "unexpected event timestamp #{entry['id']}")
  assert(actual_record == entry['expectedRecord'],
    "unexpected normalized record #{entry['id']}: keys=#{actual_record&.keys&.sort}")
end

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
