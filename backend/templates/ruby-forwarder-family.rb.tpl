# STELLAR_INIT_BEGIN
require 'json'
require 'csv'
require 'base64'
require 'ipaddr'
require 'time'
require 'date'
require 'zlib'

def initialize()
  @parser_rule_set = JSON.parse(Base64.strict_decode64('__PARSER_PROJECT_B64__'))
  @parserstudio_case_map = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64('__PARSERSTUDIO_UNICODE_CASE_B64__')))
  @parserstudio_official_types = JSON.parse('__STELLAR7_ENRICH_TYPES_JSON__')
end
# STELLAR_INIT_END

# STELLAR_PARSE_BEGIN
def parserstudio_extract(text)
  raise ArgumentError, 'Record is longer than the configured message limit' if text.bytesize > @parser_rule_set['receiver']['messageLengthLimit']
  settings = @parser_rule_set['extraction']
  # No arbitrary prefix slicing: only declared relay hostname(s) and a full
  # strict Syslog envelope qualify for an extra wrapper layer.
  text, relay_hops = parserstudio_unwrap_declared_relays(text, settings)
  # Only bounded TCP LF LF framed Java and JSON source modes can contain LF.
  # Every other source is strictly one line, never implicit reconstruction.
  framing = @parser_rule_set['receiver']['tcpFraming']
  if settings['format'] == 'java_stacktrace'
    raise ArgumentError, 'Java stack trace requires explicit LF LF TCP framing' unless
      framing == 'blank_line_java'
  elsif settings['format'] != 'json' && (text.include?("\n") || text.include?("\r"))
    raise ArgumentError, 'Multiline unframed event is unsupported'
  end
  result = case settings['format']
  when 'json'
    parserstudio_json_object(text)
  when 'java_stacktrace'
    parserstudio_java_stacktrace(text)
  when 'kv'
    parserstudio_key_values(text)
  when 'csv'
    parserstudio_csv(text, settings)
  when 'mixed'
    parserstudio_mixed(text,settings)
  when 'syslog_rfc3164'
    parserstudio_syslog_rfc3164(text, settings)
  when 'syslog_rfc5424'
    parserstudio_syslog_rfc5424(text, settings)
  when 'cef'
    parserstudio_cef(text)
  when 'leef'
    parserstudio_leef(text)
  else
    raise ArgumentError, 'Unsupported extraction format'
  end
  result['__parserstudio_forwarder_hops'] = relay_hops unless relay_hops.empty?
  result
end

# Only explicitly registered relay host identities are eligible for removal.
# Text alone cannot authenticate that sender: the caller must pin a profile.
# All lengths are offsets in the *received* UTF-8 stream, never decoded chars.
def parserstudio_unwrap_declared_relays(text, settings)
  profile = settings['forwarder']
  return [text, []] if profile.nil?
  hosts = profile['relayHosts']
  raise ArgumentError, 'Invalid forwarder configuration' unless
    hosts.is_a?(Array) && hosts.length.between?(1, 8) &&
    profile['maxHops'].is_a?(Integer) && profile['maxHops'].between?(1, 3)
  remaining=text
  consumed=0
  hops=[]
  loop do
    break unless remaining.start_with?('<')
    # Full RFC headers (including PRI, timestamp and SD) are required.
    rfc5424=remaining.match?(/\A<\d{1,3}>1 /)
    parsed=if rfc5424
      parserstudio_syslog_rfc5424(remaining, {'syslogBodyFormat'=>'raw'})
    else
      parserstudio_syslog_rfc3164(remaining, {'syslogBodyFormat'=>'raw'})
    end
    host=parsed['syslog_hostname']
    break unless hosts.include?(host)
    raise ArgumentError, 'Forwarder maximum hops exceeded' if hops.length>=profile['maxHops']
    payload=parsed['message']
    raise ArgumentError, 'Forwarder payload missing' unless payload.is_a?(String) &&
      !payload.empty? && payload.bytesize<remaining.bytesize &&
      remaining.end_with?(payload)
    prefix_len=remaining.bytesize-payload.bytesize
    hops << {
      'relay_host'=>host,
      'relay_timestamp'=>parsed['syslog_timestamp'],
      'envelope'=>rfc5424 ? 'rfc5424' : 'rfc3164',
      'prefix_start_byte'=>consumed,
      'payload_start_byte'=>consumed+prefix_len
    }
    consumed+=prefix_len
    remaining=payload
  end
  [remaining,hops]
end

# Strict Java exception/stack-frame grammar; not Java code execution.
# Each complete event MUST be supplied by TCP with the fixed LF LF delimiter.
# No arbitrary regex, multiline UDP, unbounded buffers or fallback text parsing.
def parserstudio_java_stacktrace(text)
  raise ArgumentError, 'Unframed or excessive stack trace' if text.bytesize > 8192 ||
    text.include?("\r") || text.include?("\n\n") || !text.include?("\n")
  lines = text.split("\n", -1)
  raise ArgumentError, 'Invalid Java stack physical boundaries' unless
    lines.length.between?(2, 64) && lines.all? { |line| !line.empty? && line.bytesize <= 512 }
  qualified = /(?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error)/
  header = /\A(#{qualified.source})(?:: [^\n]{1,256})?\z/.match(lines[0])
  raise ArgumentError, 'Unsupported Java exception header' unless header
  frame = /\A[ \t]+at [A-Za-z_$][A-Za-z0-9_.$\/]*\((?:[A-Za-z0-9_.$\/-]+\.java:\d{1,5}|Unknown Source|Native Method)\)\z/
  cause = /\ACaused by: (#{qualified.source})(?:: [^\n]{1,256})?\z/
  more = /\A[ \t]*\.\.\. (?:[1-9]\d{0,2}) more\z/
  frames = 0
  causes = 0
  cause_class = nil
  last = :header
  lines.drop(1).each do |line|
    if frame.match?(line)
      frames += 1
      last = :frame
    elsif (match = cause.match(line))
      causes += 1
      raise ArgumentError, 'Too many Java causes' if causes > 4
      cause_class = match[1]
      last = :cause
    elsif more.match?(line) && causes > 0 && last == :frame
      last = :more
    else
      raise ArgumentError, 'Unsupported or orphaned Java stack line'
    end
  end
  raise ArgumentError, 'Missing Java stack frame' if frames < 1 || last == :cause
  result = {'exception_class' => header[1], 'frame_count' => frames}
  result['cause_class'] = cause_class if cause_class
  result
end

# Original-source duplicate object keys cannot silently use the last value.
# Input has already passed JSON.parse syntax validation. Scan only ASCII JSON
# punctuation as bytes; JSON strings are decoded solely when followed by a
# member-name colon. Distinct objects each receive a separate key scope.
def parserstudio_json_duplicate_keys?(raw)
  stack = []
  index = 0
  bytes = raw.bytesize
  while index < bytes
    char = raw.getbyte(index)
    case char
    when 123
      stack << {}
    when 91
      stack << nil
    when 125, 93
      stack.pop
    when 34
      start = index
      index += 1
      while index < bytes
        current = raw.getbyte(index)
        if current == 92
          index += 2
          next
        end
        break if current == 34
        index += 1
      end
      index += 1
      scope = stack.last
      if scope.is_a?(Hash)
        probe = index
        while probe < bytes && [9, 10, 13, 32].include?(raw.getbyte(probe))
          probe += 1
        end
        if raw.getbyte(probe) == 58
          key = JSON.parse(raw.byteslice(start, index - start))
          return true if scope.key?(key)
          scope[key] = true
        end
      end
      next
    end
    index += 1
  end
  false
end

# Reject source JSON number tokens that JavaScript would round or underflow.
# Scan the original UTF-8 bytes, skipping quoted strings, before accepting
# JSON.parse results as parity-safe with the browser review.
def parserstudio_json_unsafe_number?(raw)
  data = raw.b
  offset = 0
  number_token = /\G-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/
  while offset < data.bytesize
    byte = data.getbyte(offset)
    if byte == 34
      offset += 1
      while offset < data.bytesize
        current = data.getbyte(offset)
        if current == 92
          offset += 2
        elsif current == 34
          offset += 1
          break
        else
          offset += 1
        end
      end
      next
    end
    if byte == 45 || (byte >= 48 && byte <= 57)
      found = number_token.match(data, offset)
      return true unless found && found.begin(0) == offset
      token = found[0]
      begin
        number = Float(token)
        return true unless number.finite?
        return true if number == number.to_i && number.abs > 9007199254740991
      rescue ArgumentError, RangeError
        return true
      end
      if token.match?(/[.eE]/)
        mantissa = token.split(/[eE]/, 2)[0]
        significant = mantissa.sub(/\A[+-]?0*/, '').delete('.').sub(/0+\z/, '')
        return true if significant.length > 15
        return true if number.zero? && mantissa.match?(/[1-9]/)
      end
      offset = found.end(0)
      next
    end
    offset += 1
  end
  false
end

def parserstudio_json_object(text)
  decoded = JSON.parse(text)
  raise ArgumentError, 'Duplicate JSON object key' if parserstudio_json_duplicate_keys?(text)
  raise ArgumentError, 'Unsafe JSON numeric precision' if parserstudio_json_unsafe_number?(text)
  raise ArgumentError, 'JSON root must be an object' unless decoded.is_a?(Hash)
  depth_limit = @parser_rule_set['extraction']['maxDepth'] || 8
  parserstudio_validate_json_depth(decoded, 0, depth_limit)
  decoded
end

def parserstudio_validate_json_depth(value, depth, limit)
  raise ArgumentError, 'Maximum JSON nesting depth exceeded' if depth > limit
  if value.is_a?(Hash)
    value.each do |key, item|
      raise ArgumentError, 'Invalid JSON source key encoding' unless key.valid_encoding?
      parserstudio_validate_json_depth(item, depth + 1, limit)
    end
  elsif value.is_a?(Array)
    value.each { |item| parserstudio_validate_json_depth(item, depth + 1, limit) }
  elsif value.is_a?(String)
    # Ruby JSON.parse can admit lone low-surrogate escapes as invalid UTF-8.
    # Reject them instead of passing invalid JSON strings to Stellar.
    raise ArgumentError, 'Invalid JSON source text encoding' unless value.valid_encoding?
  end
end

def parserstudio_unescape(text)
  # Only reviewed escape sequences are decoded. All other backslashes,
  # including Windows path separators, stay byte-for-byte intact.
  text.gsub(/\\(.)/m) do |escaped|
    next_char = escaped[1]
    ['\\', '"', "'", '='].include?(next_char) ? next_char : escaped
  end
end

# A strict small-subset token parser. No unmatched suffix can be silently lost.
def parserstudio_key_values(text)
  record = {}
  pattern = /\G[ \t]*([A-Za-z_][A-Za-z0-9_.-]{0,95})=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s"'\\])+))/
  position = 0
  while position < text.length
    tail = text[position..-1]
    break if tail.nil? || tail.strip.empty?
    match = pattern.match(text, position)
    raise ArgumentError, 'Unsupported or malformed key value segment' if match.nil?
    key = match[1]
    raise ArgumentError, 'Unsafe key value field' if ['__proto__', 'constructor', 'prototype'].include?(key)
    raise ArgumentError, 'Too many key value fields' if record.length >= 100
    raise ArgumentError, 'Duplicate key value field' if record.key?(key)
    value = match[2] || match[3] || match[4]
    record[key] = parserstudio_unescape(value)
    raise ArgumentError, 'No progress parsing key value pairs' if match.end(0) <= position
    position = match.end(0)
  end
  raise ArgumentError, 'No key value pairs found' if record.empty?
  record
end

def parserstudio_csv(text, settings)
  fields = settings['csvColumns']
  raise ArgumentError, 'CSV column names required' unless fields.is_a?(Array) && !fields.empty?
  separator = settings['csvDelimiter'] || ','
  row = CSV.parse_line(text, col_sep: separator, liberal_parsing: false, strip: true)
  raise ArgumentError, 'No CSV event parsed' unless row.is_a?(Array)
  raise ArgumentError, 'CSV column count mismatch' unless row.length == fields.length
  Hash[fields.zip(row)]
end

# A validated, bounded RFC5424 SD-ELEMENT subset, preserving source SD bytes.
# No arbitrary Grok/regex or executable parameter syntax is accepted.
def parserstudio_rfc5424_sd_name(rest, offset)
  start = offset
  while offset < rest.bytesize
    byte = rest.getbyte(offset)
    # Printable ASCII, with [ and backslash intentionally excluded in the
    # reviewed subset in addition to RFC SD-NAME reserved punctuation.
    break unless byte >= 33 && byte <= 126 &&
      ![34, 61, 91, 92, 93].include?(byte)
    offset += 1
  end
  count = offset - start
  raise ArgumentError, 'Invalid RFC5424 SD identifier or parameter' unless count >= 1 && count <= 32
  [rest.byteslice(start, count), offset]
end

def parserstudio_rfc5424_sd(rest)
  if rest.start_with?('-')
    raise ArgumentError, 'Malformed RFC5424 NILVALUE' unless rest == '-' || rest.start_with?('- ')
    return ['-', rest == '-' ? nil : rest[2..-1], {}]
  end
  raise ArgumentError, 'RFC5424 SD block required' unless rest.start_with?('[')
  offset = 0
  seen_ids = {}
  elements = {}
  while rest.getbyte(offset) == 91 # [
    offset += 1
    sd_id, offset = parserstudio_rfc5424_sd_name(rest, offset)
    raise ArgumentError, 'Repeated RFC5424 SD identifier' if seen_ids.key?(sd_id)
    seen_ids[sd_id] = true
    seen_params = {}
    params = {}
    while rest.getbyte(offset) == 32 # SPACE introduces a parameter
      offset += 1
      name, offset = parserstudio_rfc5424_sd_name(rest, offset)
      raise ArgumentError, 'Repeated RFC5424 SD parameter' if seen_params.key?(name)
      seen_params[name] = true
      raise ArgumentError, 'Missing RFC5424 SD parameter equals' unless rest.getbyte(offset) == 61
      offset += 1
      raise ArgumentError, 'Missing RFC5424 quoted SD value' unless rest.getbyte(offset) == 34
      offset += 1
      closed = false
      value = +''
      while offset < rest.bytesize
        char = rest.getbyte(offset)
        if char == 34 # closing "
          offset += 1
          closed = true
          break
        elsif char == 92 # escaped ], " or backslash
          following = rest.getbyte(offset + 1)
          raise ArgumentError, 'Invalid RFC5424 SD escape' unless [34, 92, 93].include?(following)
          value << following.chr(Encoding::UTF_8)
          offset += 2
        elsif char == 93 || char < 32 || char == 127
          raise ArgumentError, 'Unsafe or unescaped RFC5424 SD parameter character'
        else
          value << rest.byteslice(offset, 1)
          offset += 1
        end
        raise ArgumentError, 'RFC5424 SD exceeds supported bound' if offset > 1024
      end
      raise ArgumentError, 'Incomplete RFC5424 quoted SD value' unless closed
      raise ArgumentError, 'Invalid UTF-8 RFC5424 SD parameter' unless value.valid_encoding?
      safe = name.match?(/\A[A-Za-z_][A-Za-z0-9_-]{0,63}\z/) &&
        !%w[__proto__ constructor prototype].include?(name) &&
        !name.start_with?('param_hex_')
      key = safe ? name : 'param_hex_' + name.unpack1('H*')
      raise ArgumentError, 'RFC5424 SD name collision' if params.key?(key)
      params[key] = value
    end
    raise ArgumentError, 'Incomplete RFC5424 SD element' unless rest.getbyte(offset) == 93
    offset += 1
    elements['element_' + elements.size.succ.to_s] = {'sd_id' => sd_id, 'params' => params}
    raise ArgumentError, 'RFC5424 SD exceeds supported bound' if offset > 1024
  end
  structured = rest.byteslice(0, offset)
  trailing = rest.byteslice(offset..-1)
  return [structured, nil, elements] if trailing.nil? || trailing.empty?
  raise ArgumentError, 'Unsupported RFC5424 trailer' unless trailing.start_with?(' ')
  [structured, trailing.byteslice(1..-1), elements]
end

# RFC5424 strict profile; multiline and arbitrary/oversized SD remain unsupported.
def parserstudio_syslog_rfc5424(text, settings)
  pattern = /\A<(\d{1,3})>([1-9]\d?) (\S+) (\S+) (\S+) (\S+) (\S+) (.+)\z/
  match = pattern.match(text)
  raise ArgumentError, 'Unsupported RFC5424 syslog header' unless match
  # This export implements the RFC5424 VERSION=1 subset only. Reject all
  # future/unknown versions before normalization can imply support.
  raise ArgumentError, 'Unsupported RFC5424 version' unless match[2] == '1'
  # RFC5424 printable US-ASCII HEADER fields with bounded octet lengths;
  # "-" is a valid NILVALUE within those bounds.
  {4 => 255, 5 => 48, 6 => 128, 7 => 32}.each do |field, maximum|
    token = match[field]
    raise ArgumentError, 'Invalid RFC5424 header token' unless
      token.bytesize <= maximum && token.match?(/\A[!-~]+\z/)
  end
  priority = Integer(match[1], 10)
  raise ArgumentError, 'RFC5424 PRI out of range' unless priority >= 0 && priority <= 191
  # RFC5424 timestamp is NILVALUE or explicit offset-bearing RFC3339.
  # Reject malformed metadata before downstream optional field selection.
  if match[3] != '-'
    raise ArgumentError, 'Invalid RFC5424 timestamp' unless
      match[3].match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/)
    Time.iso8601(match[3])
  end
  structured_data, message, sd_elements = parserstudio_rfc5424_sd(match[8])
  record = {
    'syslog_pri' => priority,
    'syslog_version' => Integer(match[2], 10),
    'syslog_timestamp' => match[3],
    'syslog_hostname' => match[4],
    'syslog_appname' => match[5],
    'syslog_procid' => match[6],
    'syslog_msgid' => match[7],
    'syslog_structured_data' => structured_data
  }
  record['syslog_sd'] = sd_elements unless sd_elements.empty?
  if message && !message.empty?
    format = settings['syslogBodyFormat'] || 'raw'
    case format
    when 'raw'
      record['message'] = message
    when 'json'
      record['body'] = parserstudio_json_object(message)
    when 'kv'
      record['body'] = parserstudio_key_values(message)
    when 'cef'
      record['body'] = parserstudio_cef(message)
    when 'leef'
      record['body'] = parserstudio_leef(message)
    when 'regex'
      record['body'] = parserstudio_regex(message, settings)
    else
      raise ArgumentError, 'Unsupported syslog body format'
    end
  end
  record
end

# Strict single-line RFC3164 PRI + BSD HEADER + TAG: MSG subset.
# Unlike RFC5424, RFC3164's month/day/time has NO year or timezone.
# Never synthesize either, even when the host clock happens to be available.
def parserstudio_syslog_rfc3164(text, settings)
  tagged = /\A<(\d{1,3})>([A-Z][a-z]{2})[ ]+(\d{1,2})[ ]+(\d{2}):(\d{2}):(\d{2})[ ]+([!-~]{1,255})[ ]+([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[(\d{1,8})\])?:[ ]+(.+)\z/.match(text)
  # Some security appliances emit the BSD timestamp + host header without PRI
  # and TAG, followed immediately by an explicit structured body. This remains
  # a bounded grammar: raw/prose bodies are never accepted by the tagless path.
  tagless = tagged.nil? ? /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2})[ ]+(\d{1,2})[ ]+(\d{2}):(\d{2}):(\d{2})[ ]+([!-~]{1,255})[ ]+(.+)\z/.match(text) : nil
  match = tagged || tagless
  raise ArgumentError, 'Unsupported RFC3164 header' unless match
  priority = match[1] ? Integer(match[1], 10) : nil
  raise ArgumentError, 'RFC3164 PRI out of range' if priority && !priority.between?(0, 191)
  months = {'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,
    'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}
  days = months[match[2]]
  day = Integer(match[3], 10)
  hour = Integer(match[4], 10)
  minute = Integer(match[5], 10)
  second = Integer(match[6], 10)
  raise ArgumentError, 'RFC3164 calendar value is invalid' unless days &&
    day.between?(1, days) && hour.between?(0, 23) &&
    minute.between?(0, 59) && second.between?(0, 59)
  # The year may be leap-year or non-leap-year: Feb 29 is not fabricated.
  # An operator must supply a separate explicit timestamp policy to resolve it.
  timestamp = "#{match[2]} #{day.to_s.rjust(2, ' ')} #{match[4]}:#{match[5]}:#{match[6]}"
  record = {
    'syslog_timestamp' => timestamp,
    'syslog_time_policy' => 'YEAR_AND_ZONE_UNKNOWN',
    'syslog_hostname' => match[7]
  }
  record['syslog_pri'] = priority if priority
  if tagged
    record['syslog_appname'] = match[8]
    record['syslog_procid'] = match[9] if match[9]
    message = match[10]
  else
    message = match[8]
  end
  format = settings['syslogBodyFormat'] || 'raw'
  raise ArgumentError, 'Tagless RFC3164 requires an explicit structured body' if
    tagless && !%w[json kv cef leef regex].include?(format)
  case format
  when 'raw'
    record['message'] = message
  when 'json'
    record['body'] = parserstudio_json_object(message)
  when 'kv'
    record['body'] = parserstudio_key_values(message)
  when 'cef'
    record['body'] = parserstudio_cef(message)
  when 'leef'
    record['body'] = parserstudio_leef(message)
  when 'regex'
    record['body'] = parserstudio_regex(message, settings)
  else
    raise ArgumentError, 'Unsupported RFC3164 message body format'
  end
  record
end

# Explicit one-line, four-family router. Dispatch uses only fixed signatures.
# Unknown and malformed inputs fail closed with static codes, NEVER fall
# through to a permissive KV/Ruby/regex fallback.
def parserstudio_mixed(text, settings)
  allowlist = settings['mixedFormats']
  raise ArgumentError, 'Mixed family allowlist required' unless allowlist.is_a?(Array)
  family =
    if text.start_with?('{')
      'json'
    elsif text.start_with?('CEF:')
      'cef'
    elsif text.start_with?('LEEF:')
      'leef'
    elsif text.match?(/\A<\d{1,3}>[A-Z][a-z]{2} /)
      # Strict RFC3164 tag/body grammar is validated below; year and zone
      # are intentionally never inferred. All other malformed envelopes fail.
      'rfc3164_envelope'
    elsif text.start_with?('<')
      # Reuse the existing strict RFC5424 parser, including PRI/version,
      # bounded header, RFC3339 time and structured-data grammar. Dispatch
      # only when the payload starts with an explicitly reviewed family.
      'rfc5424_envelope'
    elsif text.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*=/)
      'kv'
    elsif allowlist.include?('csv') && settings['csvColumns'].is_a?(Array) &&
          settings['csvColumns'].length >= 2 &&
          [',',';', "\t"].include?(settings['csvDelimiter']) &&
          text.include?(settings['csvDelimiter'])
      # An unframed row never becomes generic CSV automatically. CSV can be
      # explicitly selected only with a reviewed column and delimiter schema.
      'csv'
    end
  if family == 'rfc3164_envelope'
    # Reuse the exact yearless RFC3164 TAG: parser, then decode only
    # explicitly allowlisted CEF/LEEF/KV bodies. No body-to-KV fallback.
    syslog = parserstudio_syslog_rfc3164(text, {'syslogBodyFormat'=>'raw'})
    message = syslog.delete('message')
    branch = if message && message.start_with?('CEF:')
      'rfc3164_cef'
    elsif message && message.start_with?('LEEF:')
      'rfc3164_leef'
    elsif message && message.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*=/)
      'rfc3164_kv'
    end
    raise ArgumentError, 'Unsupported or disallowed RFC3164 body' unless
      branch && allowlist.include?(branch)
    syslog['body'] =
      case branch
      when 'rfc3164_cef' then parserstudio_cef(message)
      when 'rfc3164_leef' then parserstudio_leef(message)
      when 'rfc3164_kv' then parserstudio_key_values(message)
      else raise ArgumentError, 'Unsupported RFC3164 body'
      end
    return syslog
  end
  if family == 'rfc5424_envelope'
    # Parsing with the raw body mode is the single authoritative header and
    # SD validation. Never route malformed Syslog as generic KV/CEF fallback.
    syslog = parserstudio_syslog_rfc5424(text, {'syslogBodyFormat'=>'raw'})
    message = syslog.delete('message')
    branch = if message && message.start_with?('CEF:')
      'rfc5424_cef'
    elsif message && message.start_with?('LEEF:')
      'rfc5424_leef'
    elsif message && message.start_with?('{')
      'rfc5424_json'
    elsif message && message.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*=/)
      'rfc5424_kv'
    end
    raise ArgumentError, 'Unsupported or disallowed wrapped Syslog family' unless
      branch && allowlist.include?(branch)
    syslog['body'] =
      case branch
      when 'rfc5424_cef' then parserstudio_cef(message)
      when 'rfc5424_leef' then parserstudio_leef(message)
      when 'rfc5424_json' then parserstudio_json_object(message)
      when 'rfc5424_kv' then parserstudio_key_values(message)
      else raise ArgumentError, 'Unsupported Syslog body family'
      end
    return syslog
  end
  raise ArgumentError, 'Unknown or disallowed mixed event family' unless
    family && allowlist.include?(family)
  case family
  when 'json'
    parserstudio_json_object(text)
  when 'kv'
    parserstudio_key_values(text)
  when 'cef'
    parserstudio_cef(text)
  when 'leef'
    parserstudio_leef(text)
  when 'csv'
    parserstudio_csv(text,settings)
  else
    raise ArgumentError, 'Unsupported mixed family'
  end
end

def parserstudio_split_escaped(text, delimiter, maximum_splits)
  parts = []
  buffer = +''
  escaped = false
  text.each_char do |character|
    if escaped
      if character == delimiter || character == '\\'
        buffer << character
      else
        buffer << '\\' << character
      end
      escaped = false
    elsif character == '\\'
      escaped = true
    elsif character == delimiter && parts.length < maximum_splits
      parts << buffer
      buffer = +''
    else
      buffer << character
    end
  end
  raise ArgumentError, 'Incomplete escaped delimited header' if escaped
  parts << buffer
  raise ArgumentError, 'Invalid delimited header' unless parts.length == maximum_splits + 1
  parts
end

# CEF extension values may contain spaces. The last whitespace byte before
# a following explicit key= token is structural; preceding whitespace belongs
# to the current value. Generic KV behavior stays strict and unchanged.
def parserstudio_cef_extensions(text)
  record = {}
  position = 0
  count = 0
  key_pattern = /\G([A-Za-z_][A-Za-z0-9_.-]{0,127})=/
  while position < text.length
    position += 1 while position < text.length && [' ', "\t"].include?(text[position])
    break if position >= text.length
    raise ArgumentError, 'CEF extension field limit exceeded' if count >= 1024
    match = key_pattern.match(text, position)
    raise ArgumentError, 'Unsupported CEF extension key boundary' if match.nil? || match.begin(0) != position
    key = match[1]
    raise ArgumentError, 'Unsafe CEF extension key' if ['__proto__','constructor','prototype'].include?(key)
    raise ArgumentError, 'Duplicate CEF extension field' if record.key?(key)
    cursor = match.end(0)
    value = +''
    boundary = nil
    while cursor < text.length
      char = text[cursor]
      if char == '\\'
        raise ArgumentError, 'Truncated CEF escape' if cursor + 1 >= text.length
        following = text[cursor + 1]
        value << case following
                 when 'n' then "\n"
                 when 'r' then "\r"
                 when '=' then '='
                 when '\\' then '\\'
                 else "\\" + following
                 end
        cursor += 2
        next
      end
      if char == ' ' || char == "\t"
        run_end = cursor
        run_end += 1 while run_end < text.length && [' ', "\t"].include?(text[run_end])
        next_key = key_pattern.match(text, run_end)
        if next_key && next_key.begin(0) == run_end
          value << text[cursor...(run_end - 1)] if run_end - cursor > 1
          boundary = run_end - 1
          break
        end
      end
      value << char
      cursor += 1
    end
    value = value.sub(/[ \t]+\z/, '') if boundary.nil?
    record[key] = value
    count += 1
    position = boundary.nil? ? text.length : boundary + 1
  end
  raise ArgumentError, 'No CEF extension fields parsed' if record.empty?
  record
end

# CEF:0|vendor|product|version|signature|name|severity|key=value ...
# Delimited header escape rules are supported. CEF extensions use their
# standard whitespace-aware key boundary semantics, not generic KV tokenization.
def parserstudio_cef(text)
  match = /\ACEF:(\d+)\|(.*)\z/m.match(text)
  raise ArgumentError, 'Invalid CEF preamble' unless match
  # This compiler implements CEF version 0 only, not vendor-specific upgrades.
  raise ArgumentError, 'Unsupported CEF version' unless match[1] == '0'
  fields = parserstudio_split_escaped(match[2], '|', 6)
  record = {
    'cef_version' => match[1],
    'cef_device_vendor' => fields[0],
    'cef_device_product' => fields[1],
    'cef_device_version' => fields[2],
    'cef_signature_id' => fields[3],
    'cef_name' => fields[4],
    'cef_severity' => fields[5]
  }
  extension = fields[6]
  unless extension.nil? || extension.strip.empty?
    extension_fields = parserstudio_cef_extensions(extension)
    raise ArgumentError, 'CEF extension overrides reserved header field' unless
      (record.keys & extension_fields.keys).empty?
    record.merge!(extension_fields)
  end
  record
end

# Basic LEEF 1.0 (TAB extension) and 2.0 (declared one-character delimiter).
def parserstudio_leef(text)
  match = /\ALEEF:(1\.0|2\.0)\|(.*)\z/m.match(text)
  raise ArgumentError, 'Invalid LEEF preamble' unless match
  version = match[1]
  parts = parserstudio_split_escaped(match[2], '|', version == '2.0' ? 5 : 4)
  record = {
    'leef_version' => version,
    'leef_vendor' => parts[0],
    'leef_product' => parts[1],
    'leef_product_version' => parts[2],
    'leef_event_id' => parts[3]
  }
  delimiter = version == '2.0' ? parts[4] : "\t"
  if version == '2.0' && (hex = /\A0x([0-9a-fA-F]{1,2})\z/.match(delimiter))
    delimiter = Integer(hex[1], 16).chr
  end
  # Keep key=value unambiguous. Bounded accepted separators: TAB or
  # printable ASCII excluding space, equals and backslash.
  valid_separator = delimiter.bytesize == 1 &&
    (delimiter == "\t" ||
     (delimiter.ord >= 33 && delimiter.ord <= 126 &&
      delimiter != '=' && delimiter != '\\'))
  raise ArgumentError, 'Unsupported LEEF delimiter' unless valid_separator
  extension = parts.last
  unless extension.nil? || extension.empty?
    extension.split(delimiter, -1).each do |piece|
      raise ArgumentError, 'Empty LEEF extension token' if piece.empty?
      key, value = piece.split('=', 2)
      raise ArgumentError, 'Malformed LEEF extension' unless key && value && key.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*\z/)
      raise ArgumentError, 'Unsafe LEEF field' if ['__proto__', 'constructor', 'prototype'].include?(key)
      raise ArgumentError, 'Duplicate LEEF field' if record.key?(key)
      record[key] = value
    end
  end
  record
end

# __PARSERSTUDIO_CANONICAL_OPERATORS__
# STELLAR_PARSE_END
