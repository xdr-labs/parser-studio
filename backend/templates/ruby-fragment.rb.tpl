# STELLAR_INIT_BEGIN
require 'json'
require 'csv'
require 'base64'
require 'ipaddr'
require 'time'

def initialize()
  @parser_rule_set = JSON.parse(Base64.strict_decode64('__PARSER_PROJECT_B64__'))
end
# STELLAR_INIT_END

# STELLAR_PARSE_BEGIN
class ParserstudioFieldError < StandardError
  attr_reader :field
  def initialize(field)
    @field = field
    super('invalid_mapped_field')
  end
end

def parse(text)
  if text.nil? || text.empty?
    yield nil, nil
    return
  end

  current_stage = 'extraction'
  begin
    original = parserstudio_extract(text)
    current_stage = 'normalization'
    normalized = parserstudio_normalize(original)
    current_stage = 'enrichment'
    normalized = parserstudio_enrich(normalized)
    current_stage = 'classification'
    normalized['stellar_log_index'] = parserstudio_classify(normalized)
    normalized['msg_origin'] = {
      'source' => @parser_rule_set['normalization']['msgOriginSource'],
      'category' => @parser_rule_set['normalization']['msgOriginCategory'],
      'class' => @parser_rule_set['normalization']['msgClass']
    }
    event_time = parserstudio_event_time(normalized)
    yield event_time, normalized
  rescue StandardError => e
    # Only static diagnostic codes and schema-controlled field paths are emitted.
    # Never copy raw log text or exception messages containing customer data.
    diagnostic = {
      'stellar_log_index' => 'syslog',
      'parser_err_msg' => e.is_a?(ParserstudioFieldError) ? 'MappedFieldError' : e.class.name,
      'parser_err_stage' => current_stage
    }
    diagnostic['parser_err_field'] = e.field if e.is_a?(ParserstudioFieldError)
    yield nil, diagnostic
  end
end

def parserstudio_extract(text)
  raise ArgumentError, 'Record is longer than the configured message limit' if text.bytesize > @parser_rule_set['receiver']['messageLengthLimit']
  settings = @parser_rule_set['extraction']
  # The generated receiver has no multiline event-breaker. Reject additional
  # physical lines for non-JSON logs instead of parsing an incomplete event.
  if settings['format'] != 'json' && (text.include?("\n") || text.include?("\r"))
    raise ArgumentError, 'Multiline non-JSON event is unsupported'
  end
  case settings['format']
  when 'json'
    parserstudio_json_object(text)
  when 'kv'
    parserstudio_key_values(text)
  when 'csv'
    parserstudio_csv(text, settings)
  when 'syslog_rfc5424'
    parserstudio_syslog_rfc5424(text, settings)
  when 'cef'
    parserstudio_cef(text)
  when 'leef'
    parserstudio_leef(text)
  else
    raise ArgumentError, 'Unsupported extraction format'
  end
end

def parserstudio_json_object(text)
  decoded = JSON.parse(text)
  raise ArgumentError, 'JSON root must be an object' unless decoded.is_a?(Hash)
  depth_limit = @parser_rule_set['extraction']['maxDepth'] || 8
  parserstudio_validate_json_depth(decoded, 0, depth_limit)
  decoded
end

def parserstudio_validate_json_depth(value, depth, limit)
  raise ArgumentError, 'Maximum JSON nesting depth exceeded' if depth > limit
  if value.is_a?(Hash)
    value.each_value { |item| parserstudio_validate_json_depth(item, depth + 1, limit) }
  elsif value.is_a?(Array)
    value.each { |item| parserstudio_validate_json_depth(item, depth + 1, limit) }
  end
end

def parserstudio_unescape(text)
  text.gsub(/\\(.)/m, '\1')
end

# A strict small-subset token parser. No unmatched suffix can be silently lost.
def parserstudio_key_values(text)
  record = {}
  pattern = /\G[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s])+))/
  position = 0
  while position < text.length
    tail = text[position..-1]
    break if tail.nil? || tail.strip.empty?
    match = pattern.match(text, position)
    raise ArgumentError, 'Unsupported or malformed key value segment' if match.nil?
    key = match[1]
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
  row = CSV.parse_line(text, col_sep: separator, liberal_parsing: false)
  raise ArgumentError, 'No CSV event parsed' unless row.is_a?(Array)
  raise ArgumentError, 'CSV column count mismatch' unless row.length == fields.length
  Hash[fields.zip(row)]
end

# Only bounded RFC5424 messages with '-' or a single structured-data block.
# Extra structured data, RFC3164 and multiline records require separate adapters.
def parserstudio_syslog_rfc5424(text, settings)
  pattern = /\A<(\d{1,3})>([1-9]\d?) (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[[^\]\n]{1,1024}\])(?: ([^\n]*))?\z/
  match = pattern.match(text)
  raise ArgumentError, 'Unsupported RFC5424 syslog header' unless match
  priority = Integer(match[1], 10)
  raise ArgumentError, 'RFC5424 PRI out of range' unless priority >= 0 && priority <= 191
  record = {
    'syslog_pri' => priority,
    'syslog_version' => Integer(match[2], 10),
    'syslog_timestamp' => match[3],
    'syslog_hostname' => match[4],
    'syslog_appname' => match[5],
    'syslog_procid' => match[6],
    'syslog_msgid' => match[7],
    'syslog_structured_data' => match[8]
  }
  message = match[9]
  if message && !message.empty?
    format = settings['syslogBodyFormat'] || 'raw'
    case format
    when 'raw'
      record['message'] = message
    when 'json'
      record['body'] = parserstudio_json_object(message)
    when 'kv'
      record['body'] = parserstudio_key_values(message)
    else
      raise ArgumentError, 'Unsupported syslog body format'
    end
  end
  record
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
  buffer << '\\' if escaped
  parts << buffer
  raise ArgumentError, 'Invalid delimited header' unless parts.length == maximum_splits + 1
  parts
end

# CEF:0|vendor|product|version|signature|name|severity|key=value ...
# Delimited header escape rules are supported. Extensions are a strict KV subset.
def parserstudio_cef(text)
  match = /\ACEF:(\d+)\|(.*)\z/m.match(text)
  raise ArgumentError, 'Invalid CEF preamble' unless match
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
  record.merge!(parserstudio_key_values(extension)) unless extension.nil? || extension.strip.empty?
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
  delimiter = "\t" if delimiter == '0x09' || delimiter == '0x9'
  raise ArgumentError, 'Unsupported LEEF delimiter' unless delimiter.length == 1
  extension = parts.last
  unless extension.nil? || extension.empty?
    extension.split(delimiter, -1).each do |piece|
      raise ArgumentError, 'Empty LEEF extension token' if piece.empty?
      key, value = piece.split('=', 2)
      raise ArgumentError, 'Malformed LEEF extension' unless key && value && key.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*\z/)
      raise ArgumentError, 'Duplicate LEEF field' if record.key?(key)
      record[key] = value
    end
  end
  record
end

def parserstudio_lookup(record, path)
  return record[path] if record.is_a?(Hash) && record.key?(path)
  value = record
  path.split('.').each do |segment|
    return nil unless value.is_a?(Hash) && value.key?(segment)
    value = value[segment]
  end
  value
end

def parserstudio_coerce(value, rule)
  type = rule['data_type']
  str = value.to_s
  case type
  when 'string'
    str
  when 'integer', 'port'
    raise ArgumentError, 'Invalid integer' unless str.match?(/\A[+-]?\d+\z/)
    number = Integer(str, 10)
    raise ArgumentError, 'Unsafe integer' if number.abs > 9007199254740991
    raise ArgumentError, 'Invalid port' if type == 'port' && (number < 0 || number > 65535)
    number
  when 'boolean'
    return true if value == true || str.downcase == 'true' || str == '1'
    return false if value == false || str.downcase == 'false' || str == '0'
    raise ArgumentError, 'Invalid boolean'
  when 'ip'
    IPAddr.new(str).to_s
  when 'date'
    raise ArgumentError, 'Unsupported date policy' unless rule['time_format'] == 'iso8601'
    raise ArgumentError, 'Timestamp must contain an explicit timezone' unless str.match?(/(?:Z|[+-]\d{2}:\d{2})\z/)
    (Time.iso8601(str).to_r * 1000).to_i
  else
    raise ArgumentError, 'Unsupported type'
  end
end

def parserstudio_assign(record, path, value)
  pieces = path.split('.')
  cursor = record
  pieces[0...-1].each do |piece|
    if cursor.key?(piece)
      raise ArgumentError, 'Path collision' unless cursor[piece].is_a?(Hash)
    else
      cursor[piece] = {}
    end
    cursor = cursor[piece]
  end
  raise ArgumentError, 'Duplicate mapped field' if cursor.key?(pieces.last)
  cursor[pieces.last] = value
end

def parserstudio_normalize(original)
  normalized = {}
  ignored = @parser_rule_set['normalization']['ignoreValues']
  ['topFields', 'nsFields', 'vendorFields'].each do |section|
    @parser_rule_set['normalization'][section].each do |source, rule|
      raw = parserstudio_lookup(original, source)
      next if raw.nil? || ignored.include?(raw.to_s)
      target = normalized
      if section == 'vendorFields'
        namespace = @parser_rule_set['vendor']
        target[namespace] ||= {}
        target = target[namespace]
      end
      begin
        converted = parserstudio_coerce(raw, rule)
        parserstudio_assign(target, rule['normalized_name'], converted)
      rescue StandardError
        raise ParserstudioFieldError.new(source)
      end
    end
  end
  normalized
end

def parserstudio_enrich(normalized)
  (@parser_rule_set['enrichment'] || []).each do |rule|
    field = rule['source'] || rule['target']
    begin
      operation = rule['operator']
      value = nil
      case operation
      when 'set_const'
        value = rule['value']
      when 'copy', 'lowercase', 'uppercase'
        value = parserstudio_lookup(normalized, rule['source'])
        raise ArgumentError, 'Enrichment source absent' if value.nil?
        if operation == 'lowercase' || operation == 'uppercase'
          raise ArgumentError, 'Text enrichment requires string input' unless value.is_a?(String)
          value = operation == 'lowercase' ? value.downcase : value.upcase
        end
      else
        raise ArgumentError, 'Unknown enrichment operator'
      end
      parserstudio_assign(normalized, rule['target'], value)
    rescue StandardError
      raise ParserstudioFieldError.new(field)
    end
  end
  normalized
end

def parserstudio_classify(normalized)
  @parser_rule_set['classification']['rules'].each do |rule|
    value = parserstudio_lookup(normalized, rule['field'])
    if rule['operator'] == 'exists'
      return rule['index'] unless value.nil?
    elsif rule['operator'] == 'equals'
      return rule['index'] if value == rule['value']
    end
  end
  @parser_rule_set['classification']['defaultIndex']
end

def parserstudio_event_time(normalized)
  timestamp = normalized['timestamp']
  return nil unless timestamp.is_a?(Integer)
  Time.at(timestamp / 1000.0)
end
# STELLAR_PARSE_END
