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
allowed = %w[v02_json v02_kv v02_csv v02_cef v02_leef v02_syslog_cef v02_syslog_leef
  v02_syslog3164_kv v02_syslog3164_cef v02_syslog3164_leef v02_mixed v02_json_blanks v02_mixed_rfc5424 v02_mixed_rfc3164 v02_mixed_rfc5424_bodies v02_mixed_rfc3164_cefleef v02_java_blanks v02_mixed_csv]
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
  expected_protocols = %w[v02_json_blanks v02_java_blanks].include?(slug) ? %w[tcp] : %w[tcp udp]
  assert(sources.length == expected_protocols.length &&
    sources.map { |x| x['@type'] }.sort == expected_protocols,
    'receiver protocol mismatch')
  if %w[v02_json_blanks v02_java_blanks].include?(slug)
    assert(sources.first['delimiter'] == "\n\n" &&
      sources.first['bind'] == '127.0.0.1' &&
      !conf.include?('is_delimiter_part_of_log'),
      'native TCP blank-line framing must be exactly LF LF and opt-in')
  end
  sources.each do |source|
    expected_port = slug == 'v02_mixed_rfc5424' ? '6801' : slug == 'v02_mixed_rfc3164' ? '6802' : slug == 'v02_mixed_rfc5424_bodies' ? '6803' : slug == 'v02_mixed_rfc3164_cefleef' ? '6804' : slug == 'v02_java_blanks' ? '7510' : slug == 'v02_mixed_csv' ? '7511' : '7501'
    assert(source['port'] == expected_port && source['tag'] == name &&
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
  digest_source = if slug == 'v02_mixed'
    ([item['raw']] + fixture.fetch('mixedCases').map { |row| row.fetch('raw') }).join("\n")
  elsif slug == 'v02_mixed_rfc5424'
    ([item['raw']] + fixture.fetch('mixedSyslogCases').map { |row| row.fetch('raw') }).join("\n")
  elsif slug == 'v02_mixed_rfc3164'
    ([item['raw']] + fixture.fetch('mixedRfc3164Cases').map { |row| row.fetch('raw') }).join("\n")
  elsif slug == 'v02_mixed_rfc5424_bodies'
    ([item['raw']] + fixture.fetch('mixedRfc5424BodyCases').map { |row| row.fetch('raw') }).join("\n")
  elsif slug == 'v02_mixed_rfc3164_cefleef'
    ([item['raw']] + fixture.fetch('mixedRfc3164WrappedCases').map { |row| row.fetch('raw') }).join("\n")
  elsif slug == 'v02_json_blanks'
    ([item['raw']] + fixture.fetch('blankLineCases').map { |row| row.fetch('raw') }).join("\n\n")
  elsif slug == 'v02_java_blanks'
    ([item['raw']] + fixture.fetch('javaBlankLineCases').map { |row| row.fetch('raw') }).join("\n\n")
  elsif slug == 'v02_mixed_csv'
    ([item['raw']] + fixture.fetch('mixedCsvCases').map { |row| row.fetch('raw') }).join("\n")
  else
    item['raw']
  end
  assert(Digest::SHA256.hexdigest(digest_source) ==
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
# Reviewed CSV is never implicit. Exact columns and one delimiter must be
# authorized by the schema, and unknown/malformed CSV fails with static errors.
assert(fixture['mixedCsvCases'].is_a?(Array)&&
 fixture['mixedCsvCases'].length==3,'missing fixed Native mixed CSV samples')
fixture['mixedCsvCases'].each do |item|
  assert(item.keys.sort==%w[expectedRecord expectedTime id raw slug]&&
    item['slug']=='v02_mixed_csv'&&item['raw'].bytesize<=16384,
    'unreviewed Native mixed CSV positive fixture')
  result=[]
  drivers.fetch('v02_mixed_csv').instance.parse(item['raw']) do |time,record|
    result << [time,record]
  end
  assert(result.length==1 && result[0][0].nil?&&
    item['expectedTime'].nil?&&result[0][1]==item.fetch('expectedRecord'),
    "mixed CSV #{item['id']}: normalized expected row mismatch")
end
assert(fixture['mixedCsvNegative'].is_a?(Array)&&
 fixture['mixedCsvNegative'].length==9,'missing fixed malformed mixed CSV rows')
fixture['mixedCsvNegative'].each do |item|
  assert(item.keys.sort==%w[id raw slug]&&
    item['slug']=='v02_mixed_csv'&&item['raw'].bytesize<=16384,
    'unreviewed Native mixed CSV rejection fixture')
  result=[]
  drivers.fetch('v02_mixed_csv').instance.parse(item['raw']) do |time,record|
    result << [time,record]
  end
  error_class=item['id']=='broken-quotes'?'CSV::MalformedCSVError':'ArgumentError'
  assert(result.length==1&&result[0][0].nil?&&
    result[0][1]=={'stellar_log_index'=>'syslog',
      'parser_err_msg'=>error_class,'parser_err_stage'=>'extraction'},
    "mixed CSV #{item['id']}: unsupported row not rejected")
end

# Fixed Java stack traces are LF LF framed by the validated Native CONF
# source, not magically reassembled from generic UDP or raw per-line input.
assert(fixture['javaBlankLineCases'].is_a?(Array)&&fixture['javaBlankLineCases'].length==1,
 'missing second fixed Java exception')
java_first=fixture['profiles'].find { |v| v['slug']=='v02_java_blanks' }
java_second=fixture['javaBlankLineCases'].first
assert(java_first && java_first['transport']=='blank_line_java'&&
  java_first['format']=='java_stacktrace'&&java_first['raw'].include?("\n")&&
  !java_first['raw'].include?("\n\n"),'invalid primary Java framing fixture')
assert(java_second['slug']=='v02_java_blanks'&&
  java_second['raw'].include?("\n")&&!java_second['raw'].include?("\n\n"),
  'invalid secondary Java framing fixture')
frames=[java_first['raw'],java_second['raw']].join("\n\n")+"\n\n"
parts=frames.split("\n\n").reject(&:empty?)
assert(parts.length==2, 'Native Java fixed LF LF boundary must account for both events')
parts.each_with_index do |part,i|
  expected=i==0 ? java_first : java_second
  result=[]
  drivers.fetch('v02_java_blanks').instance.parse(part) do |time,record|
    result<<[time,record]
  end
  assert(result.length==1&&result[0][0].nil?&&
    result[0][1]==expected.fetch('expectedRecord'),
    'Native Java callback did not normalize a bounded LF LF record')
end
assert(fixture['javaBlankLineNegative'].is_a?(Array)&&
  fixture['javaBlankLineNegative'].length==9,'missing Native Java fail-closed samples')
fixture['javaBlankLineNegative'].each do |item|
  assert(item.keys.sort==%w[id raw slug]&&item['slug']=='v02_java_blanks'&&
    item['raw'].bytesize<=8192,'unreviewed Java error case')
  out=[]
  drivers.fetch('v02_java_blanks').instance.parse(item['raw']) do |time,record|
    out<<[time,record]
  end
  assert(out.length==1&&out[0][0].nil?&&
    out[0][1]=={'stellar_log_index'=>'syslog',
     'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "Java #{item['id']}: malformed/unframed event must produce static error exactly once")
end

# Strict RFC3164 CEF/LEEF wrapped in mixed profile; exact callback and
# strict header time policy: never synthesize year, zone or native event_time.
assert(fixture['mixedRfc3164WrappedCases'].is_a?(Array)&&
 fixture['mixedRfc3164WrappedCases'].length==3,'missing RFC3164 CEF/LEEF cases')
fixture['mixedRfc3164WrappedCases'].each do |item|
  assert(item.keys.sort==%w[expectedRecord expectedTime id raw slug]&&
    item['slug']=='v02_mixed_rfc3164_cefleef'&&item['raw'].bytesize<=16384,
    'unreviewed RFC3164 CEF/LEEF positive fixture')
  result=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    result<<[time,record]
  end
  assert(result.length==1&&result[0][0].nil?&&item['expectedTime'].nil?&&
    result[0][1]==item.fetch('expectedRecord'),
    "RFC3164 mixed CEF/LEEF #{item['id']}: yearless callback mismatch")
end
assert(fixture['mixedRfc3164WrappedNegative'].is_a?(Array)&&
 fixture['mixedRfc3164WrappedNegative'].length==9,
 'missing RFC3164 CEF/LEEF negative fixtures')
fixture['mixedRfc3164WrappedNegative'].each do |item|
  assert(item.keys.sort==%w[id raw slug]&&
    item['slug']=='v02_mixed_rfc3164_cefleef'&&item['raw'].bytesize<=16384,
    'unreviewed RFC3164 CEF/LEEF negative fixture')
  result=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    result<<[time,record]
  end
  assert(result.length==1&&result[0][0].nil?&&
    result[0][1]=={'stellar_log_index'=>'syslog',
      'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "RFC3164 mixed CEF/LEEF #{item['id']}: non-allowlisted input must fail closed")
end
# Strict RFC5424 embedded JSON/KV mixed variants must retain their explicit
# timestamps and preserve one native callback per source, even for errors.
assert(fixture['mixedRfc5424BodyCases'].is_a?(Array) &&
  fixture['mixedRfc5424BodyCases'].length == 3, 'missing RFC5424 JSON/KV mixed golden records')
fixture['mixedRfc5424BodyCases'].each do |item|
  assert(item.keys.sort == %w[expectedRecord expectedTime id raw slug] &&
    item['slug']=='v02_mixed_rfc5424_bodies' && item['raw'].bytesize<=16384,
    'unreviewed RFC5424 JSON/KV mixed golden input')
  output=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    output << [time,record]
  end
  actual_time=if output[0] && output[0][0].respond_to?(:to_time)
    output[0][0].to_time.utc.iso8601
  else
    nil
  end
  assert(output.length==1 && actual_time==item['expectedTime'] &&
    output[0][1]==item.fetch('expectedRecord'),
    "RFC5424 JSON/KV mixed #{item['id']}: native fields or timestamp mismatch")
end
assert(fixture['mixedRfc5424BodyNegative'].is_a?(Array) &&
  fixture['mixedRfc5424BodyNegative'].length == 9, 'missing malformed RFC5424 mixed cases')
fixture['mixedRfc5424BodyNegative'].each do |item|
  assert(item.keys.sort == %w[id raw slug] &&
    item['slug']=='v02_mixed_rfc5424_bodies' && item['raw'].bytesize<=16384,
    'unreviewed RFC5424 JSON/KV mixed rejection input')
  output=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    output << [time,record]
  end
  # JSON.parse has a distinct safe STATIC exception class; never echo its
  # exception message, raw sample, or a parse offset into the diagnostic.
  static_error = item['id']=='invalid-json-object' ? 'JSON::ParserError' : 'ArgumentError'
  assert(output.length==1 && output[0][0].nil? &&
    output[0][1]=={'stellar_log_index'=>'syslog',
      'parser_err_msg'=>static_error,'parser_err_stage'=>'extraction'},
    "RFC5424 JSON/KV mixed #{item['id']}: unsupported event not rejected")
end
# Independently authored RFC3164 + KV mixed Native callbacks. This profile
# can never infer a UTC event_time/year or return raw log values on failure.
assert(fixture['mixedRfc3164Cases'].is_a?(Array) &&
  fixture['mixedRfc3164Cases'].length == 3,'missing RFC3164 mixed golden events')
fixture['mixedRfc3164Cases'].each do |item|
  assert(item.keys.sort == %w[expectedRecord expectedTime id raw slug] &&
    item['slug'] == 'v02_mixed_rfc3164' && item['raw'].bytesize <= 16384,
    'unreviewed RFC3164 mixed golden input')
  output=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    output << [time,record]
  end
  assert(output.length == 1 && output[0][0].nil? &&
    output[0][1] == item.fetch('expectedRecord') &&
    item['expectedTime'].nil?,
    "RFC3164 mixed #{item['id']}: callbacks must preserve year/zone UNKNOWN")
end
assert(fixture['mixedRfc3164Negative'].is_a?(Array) &&
  fixture['mixedRfc3164Negative'].length == 9,
  'missing RFC3164 mixed malformed corpus')
fixture['mixedRfc3164Negative'].each do |item|
  assert(item.keys.sort == %w[id raw slug] &&
    item['slug'] == 'v02_mixed_rfc3164' && item['raw'].bytesize <= 16384,
    'unreviewed RFC3164 mixed negative input')
  output=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    output << [time,record]
  end
  assert(output.length == 1 && output[0][0].nil? &&
    output[0][1] == {'stellar_log_index'=>'syslog',
      'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "RFC3164 mixed #{item['id']}: unsupported input must fail closed")
end
# Explicit RFC5424 CEF/LEEF wrapped mixed variant. Native parser callbacks
# must normalize each distinct family, preserve timestamp and reject every
# unsupported/invalid wrapper with a STATIC extraction error (no raw echo).
assert(fixture['mixedSyslogCases'].is_a?(Array) &&
  fixture['mixedSyslogCases'].length == 3,'missing wrapped mixed golden events')
fixture['mixedSyslogCases'].each do |item|
  assert(item.keys.sort == %w[expectedRecord expectedTime id raw slug] &&
    item['slug'] == 'v02_mixed_rfc5424' && item['raw'].bytesize <= 16384,
    'untrusted wrapped mixed golden source')
  output=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    output << [time,record]
  end
  actual_time=if output[0] && output[0][0].respond_to?(:to_time)
    output[0][0].to_time.utc.iso8601
  else
    nil
  end
  assert(output.length == 1 && actual_time == item['expectedTime'] &&
    output[0][1] == item.fetch('expectedRecord'),
    "Wrapped mixed #{item['id']}: native parser normalized record mismatched")
end
assert(fixture['mixedSyslogNegative'].is_a?(Array) &&
  fixture['mixedSyslogNegative'].length == 8,
  'expected bounded invalid RFC5424/mixed corpus')
fixture['mixedSyslogNegative'].each do |item|
  assert(item.keys.sort == %w[id raw slug] &&
    item['slug'] == 'v02_mixed_rfc5424' && item['raw'].bytesize <= 16384,
    'untrusted wrapped mixed negative source')
  emitted=[]
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time,record|
    emitted << [time,record]
  end
  assert(emitted.length == 1 && emitted[0][0].nil? &&
    emitted[0][1] == {'stellar_log_index'=>'syslog',
      'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "Wrapped mixed #{item['id']}: input must fail closed")
end
# Explicitly framed, newline-embedded public-synthetic JSON events. This
# uses the exact delimiter parsed from the native Fluentd CONF. The suite does
# not open a real TCP listener, send sensor logs, or claim live receiver E2E.
assert(fixture['blankLineCases'].is_a?(Array) && fixture['blankLineCases'].length == 1,
  'expected exactly one additional framed multiline JSON event')
pretty = fixture['profiles'].find { |p| p['slug'] == 'v02_json_blanks' }
assert(pretty && pretty['transport'] == 'blank_line_json' &&
  pretty['raw'].include?("\n") && !pretty['raw'].include?("\n\n"),
  'first JSON candidate must contain physical newlines but no blank separator')
extra = fixture['blankLineCases'].first
assert(extra.keys.sort == %w[expectedRecord expectedTime id raw slug] &&
  extra['slug'] == 'v02_json_blanks' && extra['id'] == 'second_pretty_json' &&
  extra['raw'].include?("\n") && !extra['raw'].include?("\n\n"),
  'reviewed framed JSON golden record is missing')
# Transport config AST already proved literal LF LF; parse the frames passed
# to the actual pinned native Fluentd parser callback.
framed_stream = [pretty['raw'],extra['raw']].join("\n\n") + "\n\n"
frames=framed_stream.split("\n\n").reject(&:empty?)
assert(frames.length == 2, 'blank-line JSON transport separator must produce two records')
frames.each_with_index do |frame,index|
  current = index == 0 ? pretty : extra
  output=[]
  drivers.fetch('v02_json_blanks').instance.parse(frame) do |time,record|
    output << [time,record]
  end
  assert(output.length == 1 && output[0][0].nil? &&
    output[0][1] == current.fetch('expectedRecord'),
    'native UTF-8 multiline JSON fragment did not preserve normalized fields')
end
# Explicit bounded mixed-family dataset; no record may silently disappear.
assert(fixture['mixedCases'].is_a?(Array) && fixture['mixedCases'].length == 3,
  'mixed corpus must have 3 additional independently authored events')
fixture['mixedCases'].each do |item|
  assert(item.keys.sort == %w[expectedRecord expectedTime id raw slug] &&
    item['slug'] == 'v02_mixed' && item['raw'].bytesize <= 16384,
    'untrusted mixed positive source')
  output = []
  drivers.fetch('v02_mixed').instance.parse(item['raw']) do |time, record|
    output << [time, record]
  end
  assert(output.length == 1 && output[0][0].nil? &&
    output[0][1] == item.fetch('expectedRecord'),
    "Mixed native profile #{item['id']} lost or changed an expected record")
end
assert(fixture['mixedNegative'].is_a?(Array) && fixture['mixedNegative'].length == 5,
  'mixed corpus needs fixed unknown, malformed and disallowed inputs')
fixture['mixedNegative'].each do |item|
  assert(item.keys.sort == %w[id raw slug] && item['slug'] == 'v02_mixed' &&
    item['raw'].bytesize <= 16384, 'unreviewed mixed negative source')
  output = []
  drivers.fetch('v02_mixed').instance.parse(item['raw']) do |time, record|
    output << [time, record]
  end
  assert(output.length == 1 && output[0][0].nil? &&
    output[0][1] == {'stellar_log_index'=>'syslog',
      'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "Mixed #{item['id']}: unexpected source matched instead of failing closed")
end
assert(fixture['negative'].is_a?(Array) && fixture['negative'].length == 9,
  'missing reviewed RFC3164 failure corpus')
fixture['negative'].each do |item|
  assert(item.keys.sort == %w[id raw slug] && item['slug'] == 'v02_syslog3164_kv' &&
    item['id'].match?(/\A[a-z_]+\z/) && item['raw'].bytesize <= 16384,
    'invalid native RFC3164 negative fixture')
  emitted = []
  drivers.fetch(item.fetch('slug')).instance.parse(item.fetch('raw')) do |time, record|
    emitted << [time, record]
  end
  assert(emitted.length == 1 && emitted[0][0].nil? &&
    emitted[0][1] == {'stellar_log_index'=>'syslog',
      'parser_err_msg'=>'ArgumentError','parser_err_stage'=>'extraction'},
    "RFC3164 negative #{item['id']}: callback must fail closed with static extraction diagnostic")
end
puts "ParserRecipe v0.2 strict native Fluentd callback/CONF AST: #{allowed.length} profiles + #{fixture['negative'].length} RFC3164 negatives + #{fixture['mixedCases'].length} mixed variants + #{fixture['mixedNegative'].length} mixed negatives + #{fixture['mixedSyslogCases'].length} wrapped RFC5424 variants + #{fixture['mixedSyslogNegative'].length} wrapped negatives + #{fixture['mixedRfc3164Cases'].length} RFC3164 mixed + #{fixture['mixedRfc3164Negative'].length} RFC3164 mixed rejects + #{fixture['mixedRfc5424BodyCases'].length} RFC5424 JSON/KV mixed + #{fixture['mixedRfc5424BodyNegative'].length} rejects + #{fixture['mixedRfc3164WrappedCases'].length} RFC3164 CEF/LEEF mixed + #{fixture['mixedRfc3164WrappedNegative'].length} rejects + two TCP blank-line Java stack traces + 9 Java rejects, + 3 reviewed mixed CSV and 9 rejects, and two TCP blank-line JSON fragments PASS (public synthetic only)"
