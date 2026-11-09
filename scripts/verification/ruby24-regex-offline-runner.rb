# Offline, fixed-synthetic CI-only generated-Ruby compatibility oracle.
# Payload is read from stdin and never written, printed, forwarded or mounted.
require 'json'
require 'base64'
require 'zlib'
require 'digest'
require 'time'
require 'date'
require 'csv'
require 'ipaddr'
profile = ARGV.fetch(0)
abort 'UNSUPPORTED_RUBY_PROFILE' unless %w[ruby24 ruby32].include?(profile)
expected_version = profile == 'ruby24' ? '2.4.9' : '3.2.11'
abort 'WRONG_NATIVE_RUBY_VERSION' unless RUBY_VERSION == expected_version
input = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64(STDIN.read.strip)))
abort 'INVALID_FIXED_SYNTHETIC_INPUT' unless
  input.keys.sort == %w[contract records] &&
  input['contract'] == 'parser-studio.synthetic-ruby24-regex.v1' &&
  input['records'].is_a?(Array) &&
  input['records'].map{|r|r['id']} == %w[regex syslog-regex-body]
result_count = 0
input['records'].each do |item|
  abort 'INVALID_SYNTHETIC_RECORD' unless
    item.keys.sort == %w[compressedRuby id sha256] &&
    item['compressedRuby'].is_a?(String) && item['compressedRuby'].length < 85000 &&
    item['sha256'].to_s.match?(/\A[0-9a-f]{64}\z/)
  ruby = Zlib::Inflate.inflate(Base64.strict_decode64(item['compressedRuby']))
  abort 'INVALID_ARTIFACT_SHA' unless Digest::SHA256.hexdigest(ruby) == item['sha256']
  abort 'UNEXPECTED_RUBY_SIZE' unless ruby.bytesize.between?(1000,120000)
  klass = Class.new
  klass.class_eval(ruby,'synthetic-generated-ruby',1)
  parser = klass.new
  ['allow', 'ALLOW'].each do |sample|
    if profile == 'ruby24'
      begin
        parser.send(:parserstudio_regex,sample,{'pattern'=>'^(?<action>ALLOW)$'})
        abort 'UNSAFE_NATIVE_RUBY24_REGEX_MATCH'
      rescue ArgumentError => e
        abort 'WRONG_RUBY24_ERROR' unless
          e.message == 'Native Regex unsupported: runtime has no Regexp timeout'
      end
    else
      begin
        output=parser.send(:parserstudio_regex,sample,{'pattern'=>'^(?<action>ALLOW)$'})
        abort 'WRONG_RUBY32_CASE_MATCH' unless
          sample == 'ALLOW' && output == {'action'=>'ALLOW'}
      rescue ArgumentError => e
        abort 'WRONG_RUBY32_REJECTION' unless
          sample == 'allow' && e.message == 'Regex parser did not match event'
      end
    end
    result_count+=1
  end
  # Execute the actual generated plugin parser callback, not only a private
  # helper. On unsupported target Ruby, extraction failures must produce a
  # diagnostic, never a false parsed event or an exception that escapes.
  ['allow', 'ALLOW', 'MALFORMED'].each do |sample|
    line = item['id'] == 'syslog-regex-body' ?
      '<14>1 2026-01-01T00:00:00Z sensor app - - - ' + sample : sample
    emitted = []
    parser.parse(line) { |event_time, record| emitted << [event_time, record] }
    abort 'UNEXPECTED_CALLBACK_COUNT' unless emitted.length == 1
    event_time, record = emitted.fetch(0)
    expected_success = profile == 'ruby32' && sample == 'ALLOW'
    if expected_success
      abort 'EXPECTED_NATIVE_CALLBACK_SUCCESS' if
        record.key?('parser_err_stage') ||
        record['stellar_log_index'] != 'syslog'
    else
      abort 'FAILED_CLOSED_CALLBACK_MISSING' unless
        event_time.nil? && record['parser_err_msg'] == 'ArgumentError' &&
        record['parser_err_stage'] == 'extraction' &&
        !record.key?('action') && !record.key?('body')
    end
    result_count += 1
  end
end
abort 'MISSING_NATIVE_CASES' unless result_count == 10
puts "SYNTHETIC_NATIVE_REGEX_PROFILE_PASS ruby=#{RUBY_VERSION} cases=#{result_count} profile=#{profile}"
