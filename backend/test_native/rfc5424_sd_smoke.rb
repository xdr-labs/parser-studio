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

# Regression oracle: a syntactically valid vendor SD block is not a single
# useful security field. Its individual values must survive in the generated parser.
juniper = '<14>1 2019-11-14T11:12:46.573+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_DENY ' \
  '[junos@67.43.156.15 source-address="10.0.0.26" source-port="37233" ' \
  'destination-address="67.43.156.13" destination-port="161" ' \
  'policy-name="MgmtAccess-trust-cleanup" reason="Denied by policy"]'
parsed_juniper = parser.parserstudio_syslog_rfc5424(juniper, {'syslogBodyFormat'=>'raw'})
expected = {
  'source-address'=>'10.0.0.26',
  'source-port'=>'37233',
  'destination-address'=>'67.43.156.13',
  'destination-port'=>'161',
  'policy-name'=>'MgmtAccess-trust-cleanup',
  'reason'=>'Denied by policy'
}
actual = parsed_juniper.dig('syslog_sd','element_1','params')
raise 'RFC5424 SD individual source fields were not emitted' unless actual == expected
raise 'RFC5424 original SD bytes were lost' unless parsed_juniper['syslog_structured_data'].include?('source-address="10.0.0.26"')
