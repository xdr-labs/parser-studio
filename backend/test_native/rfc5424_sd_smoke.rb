# Pinned native subset: structural SD parameter validation, not full RFC5424
# compliance or proprietary Stellar parser/loader certification.
require_relative 'synthetic_fixture_guard'
file = File.expand_path('../.tmp/native-fixtures/customized_sample_syslog', __dir__)
klass = Class.new
klass.class_eval(SyntheticFixtureGuard.read_source(file), file, 1)
parser = klass.new
valid = [
  '[meta@32473 action="deny" detail="a\\]b"][trace@32473 id="32"]',
  '[meta@32473 quote="say \\"hi\\"" path="a\\\\b"]'
]
invalid = [
  '[meta@32473 name=unquoted]',
  '[meta@32473 name "value"]',
  '[meta@32473 name="unterminated]',
  '[meta@32473 name="unescaped]bracket"]',
  '[meta@32473 name="invalid\\q"]',
  '[meta@32473 name="one" name="two"]',
  '[meta@32473][meta@32473]',
  '[meta@32473 bad]',
  '[meta@32473 bad="ok"]junk'
]
valid.each_with_index do |source, i|
  actual, remaining = parser.parserstudio_rfc5424_sd(source + ' src_ip=192.0.2.10 action=deny')
  raise "RFC5424 valid SD case #{i} altered" unless actual == source
  raise "RFC5424 valid SD case #{i} lost body" unless remaining == 'src_ip=192.0.2.10 action=deny'
end
invalid.each_with_index do |source, i|
  begin
    parser.parserstudio_rfc5424_sd(source)
    raise "RFC5424 invalid SD case #{i} silently accepted"
  rescue ArgumentError
    # Expected static parse error, never the input contents.
  end
end
puts "RFC5424 SD grammar: #{valid.length} valid + #{invalid.length} invalid bounded cases PASS (synthetic only)"
