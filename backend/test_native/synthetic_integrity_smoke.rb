# Offline-only negative cases. No customer/legacy parser sources.
require_relative 'synthetic_fixture_guard'
root = File.expand_path('../.tmp/native-fixtures', __dir__)
file = File.join(root, 'customized_sample_firewall')
source = SyntheticFixtureGuard.read_source(file)
raise 'Unexpected missing reference Ruby parser markers' unless source.include?('# STELLAR_PARSE_BEGIN')
rejected = 0
[
  lambda { SyntheticFixtureGuard.verify_source!(file, source + "\n# changed") },
  lambda { SyntheticFixtureGuard.read_source('/tmp/customized_sample_firewall') },
  lambda { SyntheticFixtureGuard.read_source(File.join(root, 'customized_not_generated')) },
  lambda { SyntheticFixtureGuard.read_source(File.join(root, 'customized_sample_firewall.conf') + '/extra') },
].each do |block|
  begin
    block.call
  rescue SyntheticFixtureGuard::BoundaryError
    rejected += 1
  end
end
raise 'Generated Ruby fixture integrity checks did not fail closed' unless rejected == 4
puts "Synthetic fixture source integrity: original PASS, #{rejected} unsafe cases REJECTED"
