# Fluentd v1 config parser validation of generated .conf syntax and structure.
# The generated fixed transport @include path does not exist on this dev host;
# replace that exact static include only IN MEMORY, not on disk. This is not
# an actual open socket test nor a Stellar Cyber loader/import test.
require 'fluent/config'

def assert(cond, detail)
  raise "FAILED: #{detail}" unless cond
end

root = ARGV.fetch(0)
names = %w[sample_firewall sample_kv sample_extended sample_csv sample_syslog sample_cef sample_leef sample_enriched]
names.each do |slug|
  filename = File.join(root, "customized_#{slug}.conf")
  original = File.read(filename, encoding: 'UTF-8')
  assert(original.ascii_only?, "#{slug}: CONF must be plain ASCII")
  transport_include = '  @include /etc/td-agent/transport_settings.conf'
  assert(!original.include?('@include /etc') || original.include?(transport_include), "#{slug}: unexpected include")
  conf = original.lines.reject { |line| line.strip == transport_include.strip }.join
  parsed = Fluent::Config.parse(conf, filename, root, true)
  sources = parsed.elements.select { |element| element.name == 'source' }
  assert(sources.length == 2, "#{slug}: UDP + TCP listener profile")
  assert(sources.map { |e| e['@type'] }.sort == %w[tcp udp], "#{slug}: protocols")
  sources.each do |source|
    assert(source['tag'] == "customized_#{slug}", "#{slug}: source tag")
    assert(source['port'] == '7123', "#{slug}: receiver port")
    assert(source.elements.size == 1, "#{slug}: one parser child")
    parser = source.elements.first
    assert(parser.name == 'parse' && parser['@type'] == "customized_#{slug}", "#{slug}: parse registration")
  end
  targets = parsed.elements.select { |element| element.name == 'match' }
  assert(targets.length == 1, "#{slug}: exactly one matcher")
  assert(targets[0].arg == "customized_#{slug}.**", "#{slug}: matching tag")
  assert(targets[0]['@type'] == 'rewrite_tag_filter', "#{slug}: rewrite router")
  rules = targets[0].elements
  assert(rules.size > 0 && rules.all? { |rule| rule['key'] == 'stellar_log_index' },
         "#{slug}: routes by normalized log index")
end

puts "Fluentd native CONF parser: #{names.length} generated profiles PASS (fixed include resolved only in-memory)"
