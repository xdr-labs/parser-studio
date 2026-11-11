# Real Fluentd 1.7.4 / Ruby 2.4.9 UDP reception oracle. CI only, no network namespace.
# Reads a private fixed payload from stdin, starts the real fluentd binary with the
# generated .conf (UDP 6801, bind 0.0.0.0, verbatim), sends the Cisco-published
# ASA lines as real UDP datagrams and checks what the parser plugin emitted.
#
# Harness-owned pieces (NOT Stellar's): the thin parser wrapper class that attaches
# the generated fragment to Fluent::Plugin::Parser, and an out_stdout section that
# prints what rewrite_tag_filter re-emitted. Stellar target import stays unverified.
require 'json'
require 'base64'
require 'zlib'
require 'socket'
require 'fileutils'

abort 'WRONG_RUBY' unless RUBY_VERSION == '2.4.9'
version = `fluentd --version 2>&1`.strip
abort 'WRONG_FLUENTD ' + version unless version == 'fluentd 1.7.4'

input = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64(STDIN.read.strip)))
abort 'INVALID_PAYLOAD' unless input['contract'] == 'parser-studio.ruby24-fluentd-udp.v1' &&
  input['port'] == 6801 && input['datagrams'].is_a?(Array) && input['datagrams'].length == 4
name = input.fetch('name')
abort 'INVALID_NAME' unless name =~ /\Acustomized_[a-z][a-z0-9_]{1,47}\z/

root = '/tmp/ps-udp'
FileUtils.mkdir_p(root + '/plugin')
FileUtils.mkdir_p(root + '/fragment')
# The fragment lives OUTSIDE the plugin dir: fluentd requires every *.rb file in -p.
File.write(root + '/fragment/fragment.rb', input.fetch('ruby'))
File.write(root + '/plugin/parser_' + name + '.rb', <<-RUBY)
require 'fluent/plugin/parser'
module Fluent
  module Plugin
    class ParserStudioHarnessParser < Parser
      Fluent::Plugin.register_parser('#{name}', self)
      class_eval(File.read('#{root}/fragment/fragment.rb'), 'generated-fragment', 1)
      fragment_initialize = instance_method(:initialize)
      define_method(:initialize) do
        super()
        fragment_initialize.bind(self).call
      end
    end
  end
end
RUBY
harness_tail = <<-CONF

<match threat session syslog>
  @type stdout
  <inject>
    tag_key _fluent_tag
    time_key _fluent_time
    time_type float
  </inject>
  <format>
    @type json
  </format>
</match>
CONF
File.write(root + '/fluent.conf', input.fetch('conf') + harness_tail)

stdout_path = root + '/stdout.txt'
log_path = root + '/fluentd.log'
pid = Process.spawn({'HOME' => '/tmp'}, 'fluentd', '-c', root + '/fluent.conf', '-p', root + '/plugin',
                    '--no-supervisor', '--suppress-config-dump', '-o', log_path,
                    out: stdout_path, err: root + '/stderr.txt')

fail_with = lambda do |code|
  warn code
  %w[fluentd.log stderr.txt stdout.txt].each do |file|
    path = root + '/' + file
    warn '--- ' + file + ' (last 4000 bytes)'
    body = File.exist?(path) ? File.read(path) : '(missing)'
    warn(body.length > 4000 ? body[-4000, 4000] : body)
  end
  Process.kill('TERM', pid) rescue nil
  exit 1
end

ready = false
60.times do
  sleep 0.5
  if File.exist?(log_path) && File.read(log_path).include?('fluentd worker is now running')
    ready = true
    break
  end
  if Process.waitpid(pid, Process::WNOHANG)
    fail_with.call('FLUENTD_EXITED_EARLY')
  end
end
fail_with.call('FLUENTD_NOT_READY') unless ready

# Bound check from the kernel's own table: UDP 0.0.0.0:6801 (0x1A91) must be open.
bound = File.read('/proc/net/udp').lines.any? { |line| line.split[1].to_s.upcase == '00000000:1A91' }
fail_with.call('UDP_6801_NOT_BOUND_ON_0.0.0.0') unless bound

socket = UDPSocket.new
input['datagrams'].each do |datagram|
  socket.send(datagram.fetch('raw'), 0, '127.0.0.1', input.fetch('port'))
  sleep 0.2
end
expected_positive = input['datagrams'].select { |d| d['expectedMatch'] }
# Fluentd 1.7.4 out_stdout writes through $log, so the formatted records land in the file given
# with `-o` (fluentd.log), interleaved with "[info]" lines, and not in the process stdout. Wait
# (bounded) until every expected record has been written and the non-matching datagram has been
# reported, then stop fluentd gracefully and parse the JSON lines it wrote.
read_records = lambda do
  next [] unless File.exist?(log_path)
  File.read(log_path).lines.select { |l| l.start_with?('{') }.map { |l| JSON.parse(l) rescue nil }.compact
end
50.times do
  break if read_records.call.length >= expected_positive.length &&
           File.exist?(log_path) && File.read(log_path).include?('pattern not matched')
  sleep 0.2
end
Process.kill('TERM', pid)
Process.waitpid(pid)
records = read_records.call

good = records.reject { |r| r.key?('parser_err_stage') }
errors = records.select { |r| r.key?('parser_err_stage') }
unless good.length == expected_positive.length
  warn 'RECORDS ' + JSON.generate(records)
  fail_with.call('UDP_EVENT_COUNT_MISMATCH good=' + good.length.to_s + ' want=' + expected_positive.length.to_s)
end
expected_positive.each_with_index do |datagram, index|
  record = good.fetch(index)
  mismatch = datagram.fetch('expectedStellarFields').reject { |key, value| record[key] == value }
  unless mismatch.empty? && record['_fluent_tag'] == 'syslog'
    warn 'RECORD ' + JSON.generate(record)
    fail_with.call('UDP_FIELD_MISMATCH ' + datagram['id'] + ' ' + mismatch.keys.join(','))
  end
end
# Every parsed event must reach the output with a real event time. The ASA corpus maps no
# timestamp, so this only holds when the generated parser itself supplies the receive time.
# (Stock and Stellar receivers send an event with a nil time to the "pattern not matched"
# path instead of emitting it.) Nothing in this harness fills in a missing time.
now = Time.now.to_f
good.each_with_index do |record, index|
  time = record['_fluent_time']
  unless time.is_a?(Numeric) && (time - now).abs <= 120
    warn 'RECORD ' + JSON.generate(record)
    fail_with.call('UDP_EVENT_TIME_NOT_RECEIVE_TIME index=' + index.to_s)
  end
end
# The extraction-failure datagram yields a diagnostic record without an event time. A
# receiver must not emit it as a parsed event: it is reported as "pattern not matched".
not_matched = File.read(log_path).scan('pattern not matched').length
unless errors.empty? && not_matched == 1
  warn 'ERRORS ' + JSON.generate(errors)
  fail_with.call('UDP_NONMATCH_NOT_REPORTED errors=' + errors.length.to_s + ' pattern_not_matched=' + not_matched.to_s)
end
puts 'UDP_6801_RECEPTION_PASS fluentd=1.7.4 ruby=' + RUBY_VERSION + ' bound=0.0.0.0:6801 ' \
     'datagrams=' + input['datagrams'].length.to_s + ' parsed=' + good.length.to_s +
     ' pattern_not_matched=' + not_matched.to_s + ' harness_time_compensation=false'
