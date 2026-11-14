# Executes compiled Ruby Fragments on raw log lines for the Semantic Oracle.
#
# Input (stdin, JSON):
#   {"fragments":{"<name>":"<ruby fragment>"},
#    "cases":[{"id":"...","fragment":"<name>","raw":"<one log line>"}],
#    "grammar":{...}}   (optional, see the end of this file)
# Output (stdout, JSON):
#   {"ruby":"<RUBY_VERSION>","results":{"<id>":{"calls":[[time,record],...]}
#                                      or {"raised":"<ExceptionClass>"}}}
#
# A fragment is loaded once, exactly as the shipped wrapper loads it (class_eval
# into an inner parser class), and reused for all of its cases. A raising parse
# is reported per case instead of aborting, because "the artifact raised" is a
# contract violation the oracle must attribute to one case. No Fluentd, network
# or Stellar target is involved.
#
# Must run on Ruby 2.4.9: no endless def, numbered parameters or pattern matching.
require 'json'

class OracleQuietLog
  def method_missing(*)
    nil
  end

  def respond_to_missing?(*)
    true
  end
end

class OracleBaseParser
  def initialize(*); end

  def configure(*); end

  def log
    @log ||= OracleQuietLog.new
  end
end

def oracle_plain(value)
  case value
  when Hash then value.each_with_object({}) { |(k, v), out| out[k.to_s] = oracle_plain(v) }
  when Array then value.map { |v| oracle_plain(v) }
  when String, Integer, Float, true, false, nil then value
  else value.to_s
  end
end

input = JSON.parse(STDIN.read)
abort 'INVALID_INPUT' unless input.is_a?(Hash) && input['fragments'].is_a?(Hash) && input['cases'].is_a?(Array)

parsers = {}
input['fragments'].each do |name, source|
  inner = Class.new(OracleBaseParser) do
    def set_inner_class_params(*); end

    def stellar_inner_class_get_parser_rule_set
      @parser_rule_set
    end
  end
  begin
    inner.class_eval(source.to_s, "oracle-#{name}", 1)
    parsers[name] = inner.new
  rescue StandardError, ScriptError => e
    abort "FRAGMENT_LOAD_FAILED #{name} #{e.class}"
  end
end

results = {}
input['cases'].each do |item|
  id = item['id'].to_s
  abort "DUPLICATE_CASE #{id}" if results.key?(id)
  parser = parsers[item['fragment'].to_s]
  abort "UNKNOWN_FRAGMENT #{id}" unless parser
  calls = []
  begin
    parser.parse(item['raw'].to_s) { |time, record| calls << [oracle_plain(time), oracle_plain(record)] }
    results[id] = { 'calls' => calls }
  rescue StandardError => e
    results[id] = { 'raised' => e.class.to_s }
  end
end

# Optional grammar-dialect probe: {"grammar":{"rules":{"<rule>":"<Ruby regexp source>"},"lines":[...]}}
# answers, per rule and line, the named captures (or null) so the oracle can
# compare the contract's Ruby dialect with its ECMAScript dialect.
grammar = {}
if input['grammar'].is_a?(Hash)
  lines = input['grammar']['lines'] || []
  (input['grammar']['rules'] || {}).each do |name, source|
    expression = Regexp.new(source.to_s)
    grammar[name] = lines.map do |line|
      match = expression.match(line.to_s)
      match ? Hash[match.names.zip(match.captures)] : nil
    end
  end
end

puts JSON.generate('ruby' => RUBY_VERSION, 'results' => results, 'grammar' => grammar)
