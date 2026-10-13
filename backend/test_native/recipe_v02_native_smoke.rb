# Native Ruby 3.2/Fluentd 1.17.1 proof for fixed v0.2 staged compiler
# equivalence outputs. PUBLIC SYNTHETIC events only. No user Ruby/log execution.
require 'json'
require 'digest'
require 'open3'
require 'time'
require 'fluent/config'
require 'fluent/plugin/parser'
require 'fluent/test'
require 'fluent/test/driver/parser'

def assert(value, reason)
  raise "Synthetic recipe native boundary: #{reason}" unless value
end

root = File.expand_path('../.tmp/recipe-v02-fixtures', __dir__)
manifest_path = File.expand_path('../.tmp/recipe-v02-native-manifest.json', __dir__)
golden_path = File.expand_path('fixtures/recipe-v0.2-golden.json', __dir__)
assert(ARGV.length == 1 && File.expand_path(ARGV[0]) == root,
  'only the exact fixed generated fixture directory is permitted')

def regular_source(path, max_bytes)
  file = File.open(path, File::RDONLY | File::NOFOLLOW)
  begin
    stat = file.stat
    assert(stat.file? && stat.nlink == 1 && stat.size <= max_bytes,
      'file is not an exclusive bounded regular file')
    file.read
  ensure
    file.close
  end
rescue Errno::ENOENT, Errno::ELOOP, Errno::EISDIR, Errno::EACCES
  assert(false, 'untrusted source file')
end

[root, File.dirname(root)].each do |dir|
  assert(File.lstat(dir).directory? && !File.lstat(dir).symlink? &&
    File.realpath(dir) == dir, 'untrusted synthetic fixture directory')
end
[manifest_path, golden_path].each do |path|
  assert(File.lstat(path).file? && !File.lstat(path).symlink? &&
    File.realpath(path) == path, 'untrusted synthetic fixture manifest')
end
manifest = JSON.parse(regular_source(manifest_path, 16384))
fixture = JSON.parse(regular_source(golden_path, 65536))
allowed = %w[v02_json v02_kv v02_csv v02_cef v02_leef v02_syslog_cef v02_syslog_leef]
filenames = allowed.flat_map { |slug| ["customized_#{slug}", "customized_#{slug}.conf"] }
head, status = Open3.capture2('git', 'rev-parse', 'HEAD')
assert(status.success? && manifest['backendHead'] == head.strip, 'exact HEAD mismatch')
assert(manifest['kind'] == 'parser-studio.recipe-v0.2-native-fixture-evidence.v0.1' &&
  manifest['origin'] == 'independently-authored-public-synthetic' &&
  manifest['nativeUserParserVerified'] == false &&
  manifest['targetImportVerified'] == false && manifest['sensorTrafficSent'] == false,
  'incorrect manifest verification flags')
assert(fixture['kind'] == 'parser-studio.recipe-v0.2-native-golden.v0.1' &&
  fixture['origin'] == 'independently-authored-public-synthetic' &&
  fixture['profiles'].map { |x| x['slug'] } == allowed,
  'unreviewed native golden corpus')
assert(Digest::SHA256.file(golden_path).hexdigest == manifest['fixtureSha256'],
  'golden corpus SHA does not match generated recipe evidence')
assert(manifest['files'].keys.sort == filenames.sort, 'incomplete paired fixture hashes')
assert(manifest['receipts'].is_a?(Array) && manifest['receipts'].length == allowed.length,
  'missing compiler receipts')
assert(manifest['receipts'].map { |entry| entry['slug'] } == allowed &&
  manifest['receipts'].all? do |receipt|
    receipt['recipeSha256'].match?(/\A[a-f0-9]{64}\z/) &&
      receipt['sampleSha256'].match?(/\A[a-f0-9]{64}\z/)
  end, 'untrusted recipe receipt')

files = {}
filenames.each do |filename|
  source = regular_source(File.join(root, filename), 128 * 1024)
  assert(Digest::SHA256.hexdigest(source) == manifest['files'].fetch(filename),
    'generated source differs from compiler SHA receipt')
  files[filename] = source
end

Fluent::Test.setup
assert(Gem.loaded_specs.fetch('fluentd').version.to_s == '1.17.1',
  'native Fluentd profile mismatch')
drivers = {}
allowed.each do |slug|
  name = "customized_#{slug}"
  ruby_source = files.fetch(name)
  klass = Class.new(Fluent::Plugin::Parser)
  klass.class_eval(ruby_source, File.join(root, name), 1)
  Fluent::Plugin.register_parser(name, klass)
  drivers[slug] = Fluent::Test::Driver::Parser.new(klass).configure('')

  conf_name = name + '.conf'
  original = files.fetch(conf_name)
  assert(original.ascii_only?, 'generated CONF must be ASCII')
  include_line = '  @include /etc/td-agent/transport_settings.conf'
  conf = original.lines.reject { |line| line.strip == include_line.strip }.join
  parsed = Fluent::Config.parse(conf, File.join(root, conf_name), root, true)
  sources = parsed.elements.select { |x| x.name == 'source' }
  assert(sources.length == 2 &&
    sources.map { |x| x['@type'] }.sort == %w[tcp udp], 'receiver protocol mismatch')
  sources.each do |source|
    assert(source['port'] == '7501' && source['tag'] == name &&
      source.elements.size == 1 && source.elements.first['@type'] == name,
      'generated receiver port and parser registration mismatch')
  end
  matches = parsed.elements.select { |x| x.name == 'match' }
  assert(matches.length == 1 && matches.first.arg == "#{name}.**" &&
    matches.first['@type'] == 'rewrite_tag_filter', 'generated match routing mismatch')
end

fixture['profiles'].each do |item|
  slug = item.fetch('slug')
  assert(item.fetch('raw').bytesize <= 16384, 'golden event over limit')
  assert(Digest::SHA256.hexdigest(item['raw']) ==
    manifest.fetch('receipts').find { |r| r['slug'] == slug }.fetch('sampleSha256'),
    'fixed sample hash mismatch')
  output = []
  drivers.fetch(slug).instance.parse(item.fetch('raw')) do |event_time, record|
    output << [event_time,record]
  end
  assert(output.length == 1, 'native callback event accounting mismatch')
  event_time, record = output.first
  actual_time = if event_time.nil?
    nil
  elsif event_time.respond_to?(:to_time)
    event_time.to_time.utc.iso8601
  else
    Time.at(event_time.to_r).utc.iso8601
  end
  assert(actual_time == item['expectedTime'], 'native event time mismatch')
  assert(record == item.fetch('expectedRecord'), 'native normalized fields mismatch')
end
puts "ParserRecipe v0.2 exact native Fluentd callback/CONF AST: #{allowed.length} profiles PASS (public synthetic only)"
