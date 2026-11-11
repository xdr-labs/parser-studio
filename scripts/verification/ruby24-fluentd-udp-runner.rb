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
      # Stock in_udp (1.7.4) drops a parsed event whose time is nil ("pattern not
      # matched"). The generated parser yields nil time when no timestamp field is
      # mapped, and for diagnostic error records. How Stellar's own wrapper treats a
      # nil time is NOT known, so this harness supplies the receive time and the
      # finding is reported instead of hidden.
      fragment_parse = instance_method(:parse)
      define_method(:parse) do |text, &block|
        fragment_parse.bind(self).call(text) do |time, record|
          block.call(time.nil? && !record.nil? ? Fluent::EventTime.now : time, record)
        end
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
# out_stdout writes through a block-buffered file descriptor, so records only reach the
# file when fluentd flushes at shutdown. Give the datagrams time to be processed, then
# stop fluentd gracefully (TERM flushes) and read what it wrote.
sleep 2
Process.kill('TERM', pid)
Process.waitpid(pid)
records = File.exist?(stdout_path) ? File.read(stdout_path).lines.map { |l| JSON.parse(l) rescue nil }.compact : []

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
unless errors.length == 1 && errors.first['parser_err_stage'] == 'extraction' && errors.first['_fluent_tag'] == 'syslog'
  warn 'ERRORS ' + JSON.generate(errors)
  fail_with.call('UDP_NONMATCH_DIAGNOSTIC_MISMATCH')
end
puts 'UDP_6801_RECEPTION_PASS fluentd=1.7.4 ruby=' + RUBY_VERSION + ' bound=0.0.0.0:6801 ' \
     'datagrams=' + input['datagrams'].length.to_s + ' parsed=' + good.length.to_s +
     ' nonmatching_to_diagnostic_record=' + errors.length.to_s +
     ' harness_supplied_receive_time_for_nil_time=true'
