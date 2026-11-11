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
  input['records'].map{|r|r['id']} == %w[regex regex-cisco-asa syslog-regex-body regex-unbounded generic-positional-csv csv]
result_count = 0
input['records'].each do |item|
  abort 'INVALID_SYNTHETIC_RECORD' unless
    (item.keys.sort == %w[compressedRuby id sha256] ||
     item.keys.sort == %w[compressedRuby id pattern sha256] ||
     item.keys.sort == %w[compressedRuby corpus id pattern sha256]) &&
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
  pattern = item.fetch('pattern')
  settings = {'pattern' => pattern}
  helper_error = lambda do |sample|
    begin
      parser.send(:parserstudio_regex, sample, settings)
      nil
    rescue ArgumentError => e
      e.message
    end
  end
  callback = lambda do |line|
    emitted = []
    parser.parse(line) { |event_time, record| emitted << [event_time, record] }
    abort 'UNEXPECTED_CALLBACK_COUNT' unless emitted.length == 1
    emitted.fetch(0)
  end
  unsupported = 'Native Regex unsupported: runtime has no Regexp timeout and the pattern has no static cost proof'
  if item['id'] == 'regex'
    # Hand-authored operator log and expected values: a bounded Regex MUST
    # execute natively on this runtime, with or without a Regexp timeout.
    tcp = 'May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/443 (81.2.69.144/443)'
    udp = 'May  5 17:51:18 dev01: %FTD-6-302015: Built inbound UDP connection 112 for net:10.10.10.11/53501 (81.2.69.144/53501) to fw111:192.168.2.3/53 (81.2.69.144/53)'
    abort 'REGEX_FTD_TCP_VALUES_MISMATCH' unless
      parser.send(:parserstudio_regex, tcp, settings) ==
      {'event_id'=>'302013','protocol'=>'TCP','srcip'=>'10.10.10.10','srcport'=>'53500','dstip'=>'192.168.2.2','dstport'=>'443'}
    abort 'REGEX_FTD_UDP_VALUES_MISMATCH' unless
      parser.send(:parserstudio_regex, udp, settings) ==
      {'event_id'=>'302015','protocol'=>'UDP','srcip'=>'10.10.10.11','srcport'=>'53501','dstip'=>'192.168.2.3','dstport'=>'53'}
    # Two events through the real plugin callback: values must not leak between events.
    first = callback.call(tcp)[1]
    second = callback.call(udp)[1]
    abort 'REGEX_CALLBACK_TCP_MISMATCH' unless
      !first.key?('parser_err_stage') && first['srcip'] == '10.10.10.10' &&
      first['dstip'] == '192.168.2.2' && first['protocol'] == 'TCP'
    abort 'REGEX_CALLBACK_UDP_MISMATCH' unless
      !second.key?('parser_err_stage') && second['srcip'] == '10.10.10.11' &&
      second['dstip'] == '192.168.2.3' && second['protocol'] == 'UDP'
    abort 'REGEX_NONMATCH_ACCEPTED' unless
      helper_error.call('May  5 17:51:19 dev01: %FTD-6-302014: Teardown TCP connection 111') == 'Regex parser did not match event'
    # Adversarial inputs at the proven bound: must be rejected quickly. A
    # backtracking blow-up would exceed the wall-clock limit on this runtime.
    attacks = [
      'a' * 4096,
      ('%FTD-6-1: Built inbound TCP connection 1 for a:1.1/1 ' * 80)[0, 4096],
      '1.' * 2048
    ]
    attacks.each do |attack|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      message = helper_error.call(attack)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      abort 'REGEX_ADVERSARIAL_NOT_REJECTED' unless message == 'Regex parser did not match event'
      abort 'REGEX_ADVERSARIAL_TOO_SLOW ' + elapsed.to_s unless elapsed < 1.0
    end
    abort 'REGEX_OVERSIZE_ACCEPTED' unless
      helper_error.call('a' * 4097) == 'Regex parser input exceeds the proven bound'
    abort 'REGEX_MULTILINE_ACCEPTED' unless
      helper_error.call(tcp + "\n" + udp) == 'Regex parser input exceeds the proven bound'
    result_count += 9
    next
  end
  if item['id'] == 'regex-cisco-asa'
    # Cisco-published ASA examples (VENDOR_PUBLISHED_TEXT: page bytes were not
    # capturable, so these are never labelled VENDOR_DOCUMENTED). Raw lines and
    # expected values come from the corpus file, authored independently of the
    # generated Ruby, which must reproduce every value on this runtime.
    corpus = item.fetch('corpus')
    abort 'ASA_CORPUS_SHAPE' unless corpus.is_a?(Array) && corpus.length == 4 &&
      corpus.all? { |c| c['sampleClass'] == 'VENDOR_PUBLISHED_TEXT' }
    corpus.each do |c|
      raw = c.fetch('rawSample')
      if c['expectedMatch']
        abort 'ASA_VALUES_MISMATCH ' + c['id'] unless
          parser.send(:parserstudio_regex, raw, settings) == c.fetch('expectedFields')
        record = callback.call(raw)[1]
        stellar = c.fetch('expectedStellarFields')
        abort 'ASA_CALLBACK_MISMATCH ' + c['id'] unless
          !record.key?('parser_err_stage') &&
          stellar.all? { |key, value| record[key] == value }
        result_count += 2
      else
        abort 'ASA_NONMATCH_ACCEPTED ' + c['id'] unless
          helper_error.call(raw) == 'Regex parser did not match event'
        result_count += 1
      end
    end
    next
  end
  if item['id'] == 'regex-unbounded'
    if profile == 'ruby24'
      abort 'UNPROVEN_REGEX_NOT_FAILED_CLOSED' unless helper_error.call('12345') == unsupported
      event_time, record = callback.call('12345')
      abort 'UNPROVEN_REGEX_CALLBACK_NOT_CLOSED' unless
        event_time.nil? && record['parser_err_msg'] == 'ArgumentError' &&
        record['parser_err_stage'] == 'extraction' && !record.key?('action')
    else
      abort 'RUBY32_UNBOUNDED_REGEX_MISMATCH' unless
        parser.send(:parserstudio_regex, 'id 12345', settings) == {'action'=>'12345'}
      _, record = callback.call('12345')
      abort 'RUBY32_UNBOUNDED_CALLBACK_FAILED' if record.key?('parser_err_stage')
    end
    result_count += 2
    next
  end
  # syslog-regex-body: anchored loop-free pattern, bounded on both runtimes.
  abort 'BOUNDED_REGEX_MATCH_MISMATCH' unless
    parser.send(:parserstudio_regex, 'ALLOW', settings) == {'action'=>'ALLOW'}
  abort 'BOUNDED_REGEX_CASE_ACCEPTED' unless
    helper_error.call('allow') == 'Regex parser did not match event'
  result_count += 2
  ['allow', 'ALLOW', 'MALFORMED'].each do |sample|
    event_time, record = callback.call('<14>1 2026-01-01T00:00:00Z sensor app - - - ' + sample)
    if sample == 'ALLOW'
      abort 'EXPECTED_NATIVE_CALLBACK_SUCCESS' if
        record.key?('parser_err_stage') || record['stellar_log_index'] != 'syslog'
    else
      abort 'FAILED_CLOSED_CALLBACK_MISSING' unless
        event_time.nil? && record['parser_err_msg'] == 'ArgumentError' &&
        record['parser_err_stage'] == 'extraction' &&
        !record.key?('action') && !record.key?('body')
    end
    result_count += 1
  end
end
abort 'MISSING_NATIVE_CASES' unless result_count == 28
puts "SYNTHETIC_NATIVE_TARGET_PROFILE_PASS ruby=#{RUBY_VERSION} cases=#{result_count} profile=#{profile}"
