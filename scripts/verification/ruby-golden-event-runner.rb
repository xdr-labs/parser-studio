# Executes compiled Ruby Fragments on raw log lines and prints the emitted events.
#
# Input (stdin, JSON): {"cases":[{"id":"...","ruby":"<fragment>","raw":"<one log>"}]}
# Output (stdout, JSON): {"ruby":"<RUBY_VERSION>","results":{"<id>":{"calls":[[time,record],...]}}}
#
# The fragment is loaded exactly as the shipped wrapper loads it: class_eval into
# an inner parser class that supplies the wrapper surface the fragment may call.
# No Fluentd, no network, no Stellar target: this only answers "what event does
# this downloaded Ruby emit for this raw log?" so a test can compare the result
# with independently recorded expectations.
#
# Must run on the oldest supported runtime (Ruby 2.4): no endless def, no
# numbered block parameters, no pattern matching.
require 'json'

# Minimal stand-in for Fluent::Plugin::Parser and the wrapper's inner class.
class QuietLog
  def method_missing(*)
    nil
  end

  def respond_to_missing?(*)
    true
  end
end

class BaseParser
  def initialize(*); end

  def configure(*); end

  def log
    @log ||= QuietLog.new
  end
end

def plain(value)
  case value
  when Hash then value.each_with_object({}) { |(k, v), out| out[k.to_s] = plain(v) }
  when Array then value.map { |v| plain(v) }
  when String, Integer, Float, true, false, nil then value
  else value.to_s
  end
end

input = JSON.parse(STDIN.read)
abort 'INVALID_INPUT' unless input.is_a?(Hash) && input['cases'].is_a?(Array)

results = {}
input['cases'].each do |item|
  id = item['id'].to_s
  abort "DUPLICATE_CASE #{id}" if results.key?(id)
  inner = Class.new(BaseParser) do
    def set_inner_class_params(*); end

    def stellar_inner_class_get_parser_rule_set
      @parser_rule_set
    end
  end
  begin
    inner.class_eval(item['ruby'].to_s, "golden-#{id}", 1)
    parser = inner.new
  rescue StandardError, ScriptError => e
    abort "FRAGMENT_LOAD_FAILED #{id} #{e.class}"
  end
  calls = []
  begin
    parser.parse(item['raw'].to_s) { |time, record| calls << [plain(time), plain(record)] }
  rescue StandardError => e
    abort "PARSE_RAISED #{id} #{e.class}"
  end
  results[id] = { 'calls' => calls }
end

puts JSON.generate('ruby' => RUBY_VERSION, 'results' => results)
