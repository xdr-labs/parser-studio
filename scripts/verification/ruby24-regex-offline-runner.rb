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
  input['records'].map{|r|r['id']} == %w[regex syslog-regex-body generic-positional-csv csv]
result_count = 0
input['records'].each do |item|
  abort 'INVALID_SYNTHETIC_RECORD' unless
    item.keys.sort == %w[compressedRuby id sha256] &&
    item['compressedRuby'].is_a?(String) && item['compressedRuby'].length < 150000 &&
    item['sha256'].to_s.match?(/\A[0-9a-f]{64}\z/)
  ruby = Zlib::Inflate.inflate(Base64.strict_decode64(item['compressedRuby']))
  abort 'INVALID_ARTIFACT_SHA' unless Digest::SHA256.hexdigest(ruby) == item['sha256']
  abort 'UNEXPECTED_RUBY_SIZE' unless ruby.bytesize.between?(1000,180000)
  klass = Class.new
  klass.class_eval(ruby,'synthetic-generated-ruby',1)
  parser = klass.new
  if item['id'] == 'csv'
    # Fixed, independently expected CSV values: unquoted edge spaces are
    # trimmed, quoted whitespace is preserved, embedded comma stays quoted.
    output=parser.send(:parserstudio_csv,
      '  alpha  ," quoted, value ",  gamma  ',
      {'csvColumns'=>%w[alpha bravo charlie],'csvDelimiter'=>','})
    abort 'CSV_INDEPENDENT_FIELDS_MISMATCH' unless
      output=={'alpha'=>'alpha','bravo'=>' quoted, value ','charlie'=>'gamma'}
    # TAB grammar must not silently trim fields.
    tab=parser.send(:parserstudio_csv,
      " first\t second\t third ",
      {'csvColumns'=>%w[alpha bravo charlie],'csvDelimiter'=>"\t"})
    abort 'CSV_TAB_WHITESPACE_LOST' unless
      tab=={'alpha'=>' first','bravo'=>' second','charlie'=>' third '}
    result_count+=2
    next
  end
  if item['id'] == 'generic-positional-csv'
    # A fixed independent PAN-OS source proves actual generated grammar
    # execution on both Ruby 2.4.9 and Ruby 3.2.11, not syntax alone.
    source='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy'
    result=parser.send(:parserstudio_generic_rfc3164_positional_csv,source)
    abort 'PANOS_STRUCTURAL_SOURCE_NOT_PARSED' unless
      result.is_a?(Hash) && result.dig('syslog','hostname') == 'PA-FW01' &&
      result.dig('generic','mode') == 'panos_traffic_csv' &&
      result.dig('generic','fields','src') == '10.10.20.15' &&
      result.dig('generic','fields','sport') == '51234' &&
      result.dig('generic','fields','dport') == '443' &&
      result.dig('generic','fields','action') == 'allow'
    abort 'INVALID_IPV4_ACCEPTED' if
      parser.send(:parserstudio_generic_valid_ipv4?,'256.10.20.15')
    abort 'VALID_IPV4_REJECTED' unless
      parser.send(:parserstudio_generic_valid_ipv4?,'10.10.20.15')
    result_count += 3
    next
  end
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
abort 'MISSING_NATIVE_CASES' unless result_count == 15
puts "SYNTHETIC_NATIVE_TARGET_PROFILE_PASS ruby=#{RUBY_VERSION} cases=#{result_count} profile=#{profile}"
