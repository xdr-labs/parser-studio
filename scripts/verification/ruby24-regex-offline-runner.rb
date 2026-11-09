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
end
abort 'MISSING_NATIVE_CASES' unless result_count == 4
puts "SYNTHETIC_NATIVE_REGEX_PROFILE_PASS ruby=#{RUBY_VERSION} cases=#{result_count} profile=#{profile}"
