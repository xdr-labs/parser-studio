# Offline Ruby matrix runner for every compiler variant. Payload arrives on
# stdin only; nothing is written, printed or forwarded. Run under the pinned
# Ruby 2.4.9 target image and the Ruby 3.2.11 CI image. Profile `local` accepts
# any Ruby >= 2.4 and is NON-AUTHORITATIVE (developer machines only).
#
# Per variant it proves, without trusting text patterns alone:
#   1. the fragment compiles (RubyVM::InstructionSequence) on this Ruby;
#   2. AST shape (Ripper): only definitions, assignments, requires and class
#      body helpers at top level, with def initialize and def parse(text);
#   3. embedding: the fragment loads into a stand-in for the platform wrapper's
#      inner parser class (same method surface the wrapper calls), initializes,
#      exposes @parser_rule_set as a Hash through the wrapper accessor, answers
#      empty input with `yield nil, nil` and survives arbitrary non-log input
#      by yielding well-formed values.
# The stand-in reproduces the wrapper's public surface only; it is not the
# installed wrapper and a pass is not a Stellar Cyber import result.
require 'json'
require 'base64'
require 'zlib'
require 'digest'
require 'ripper'

profile = ARGV.fetch(0)
abort 'UNSUPPORTED_RUBY_PROFILE' unless %w[ruby24 ruby32 local].include?(profile)
expected_version = { 'ruby24' => '2.4.9', 'ruby32' => '3.2.11' }[profile]
abort 'WRONG_NATIVE_RUBY_VERSION' if expected_version && RUBY_VERSION != expected_version
abort 'RUBY_TOO_OLD' if Gem::Version.new(RUBY_VERSION) < Gem::Version.new('2.4.0')

input = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64(STDIN.read.strip)))
abort 'INVALID_VARIANT_MATRIX_INPUT' unless input['contract'] == 'parser-studio.variant-matrix.v1' &&
  input['variants'].is_a?(Array) && input['count'] == input['variants'].length && input['count'] > 0

ALLOWED_COMMANDS = %w[require require_relative private public protected attr_reader attr_writer attr_accessor include extend].freeze
SIMPLE_STATEMENTS = %i[def assign opassign class module void_stmt].freeze

def statement_ok?(statement)
  return true if SIMPLE_STATEMENTS.include?(statement[0])
  case statement[0]
  when :command then ALLOWED_COMMANDS.include?(statement[1][1])
  when :vcall then %w[private public protected].include?(statement[1][1])
  else false
  end
end

def defined_methods(statements)
  statements.select { |s| s[0] == :def }.map { |s| [s[1][1], s[2]] }
end

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

passed = 0
input['variants'].each do |item|
  id = item['id']
  abort "INVALID_VARIANT_RECORD #{id}" unless item.keys.sort == %w[compressedRuby id sha256] &&
    item['sha256'].to_s.match?(/\A[0-9a-f]{64}\z/)
  ruby = Zlib::Inflate.inflate(Base64.strict_decode64(item['compressedRuby']))
  abort "ARTIFACT_SHA_MISMATCH #{id}" unless Digest::SHA256.hexdigest(ruby) == item['sha256']

  begin
    RubyVM::InstructionSequence.compile(ruby, id)
  rescue SyntaxError => e
    abort "RUBY_SYNTAX_ERROR #{id} #{e.message.lines.first.to_s.strip[0, 200]}"
  end

  sexp = Ripper.sexp(ruby)
  abort "RIPPER_PARSE_FAILED #{id}" unless sexp && sexp[0] == :program
  statements = sexp[1]
  offenders = statements.reject { |s| statement_ok?(s) }.map { |s| s[0] }.uniq
  abort "TOP_LEVEL_EXECUTABLE_STATEMENT #{id} #{offenders.inspect}" unless offenders.empty?
  methods = defined_methods(statements).to_h
  abort "MISSING_INITIALIZE #{id}" unless methods.key?('initialize')
  abort "MISSING_PARSE #{id}" unless methods.key?('parse')
  parse_params = methods['parse']
  parse_params = parse_params[1] if parse_params.is_a?(Array) && parse_params[0] == :paren
  abort "PARSE_ARITY #{id}" unless parse_params.is_a?(Array) && parse_params[0] == :params &&
    parse_params[1].is_a?(Array) && parse_params[1].length == 1

  inner = Class.new(BaseParser) do
    def set_inner_class_params(*); end
    def stellar_inner_class_get_parser_rule_set; @parser_rule_set; end
  end
  begin
    inner.class_eval(ruby, "variant-#{id}", 1)
    parser = inner.new
  rescue StandardError, ScriptError => e
    abort "FRAGMENT_LOAD_FAILED #{id} #{e.class}"
  end
  abort "RULE_SET_NOT_HASH #{id}" unless parser.stellar_inner_class_get_parser_rule_set.is_a?(Hash)

  calls = []
  begin
    parser.parse('') { |time, record| calls << [time, record] }
  rescue StandardError => e
    abort "PARSE_RAISED_ON_EMPTY_INPUT #{id} #{e.class}"
  end
  abort "EMPTY_INPUT_CONTRACT #{id}" unless calls == [[nil, nil]]

  calls = []
  begin
    parser.parse("\x01 not a log \x02") { |time, record| calls << [time, record] }
  rescue StandardError => e
    abort "PARSE_RAISED_ON_NON_LOG #{id} #{e.class}"
  end
  abort "NON_LOG_NO_YIELD #{id}" if calls.empty?
  abort "NON_LOG_BAD_YIELD #{id}" unless calls.all? { |_, record| record.nil? || record.is_a?(Hash) || record.is_a?(Array) }
  passed += 1
end
abort 'MISSING_VARIANTS' unless passed == input['count']
puts "RUBY_VARIANT_MATRIX_PASS ruby=#{RUBY_VERSION} variants=#{passed} profile=#{profile}"
