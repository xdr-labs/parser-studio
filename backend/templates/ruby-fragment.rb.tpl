# STELLAR_INIT_BEGIN
require 'json'
require 'base64'
require 'ipaddr'
require 'time'

def initialize()
  @parser_rule_set = JSON.parse(Base64.strict_decode64('__PARSER_PROJECT_B64__'))
end
# STELLAR_INIT_END

# STELLAR_PARSE_BEGIN
def parse(text)
  if text.nil? || text.empty?
    yield nil, nil
    return
  end

  begin
    original = parserstudio_extract(text)
    normalized = parserstudio_normalize(original)
    normalized['stellar_log_index'] = parserstudio_classify(normalized)
    normalized['msg_origin'] = {
      'source' => @parser_rule_set['normalization']['msgOriginSource'],
      'category' => @parser_rule_set['normalization']['msgOriginCategory'],
      'class' => @parser_rule_set['normalization']['msgClass']
    }
    event_time = parserstudio_event_time(normalized)
    yield event_time, normalized
  rescue StandardError => e
    # No original sensitive log text is included in a parser failure.
    yield nil, { 'stellar_log_index' => 'syslog', 'parser_err_msg' => e.class.name }
  end
end

def parserstudio_extract(text)
  mode = @parser_rule_set['extraction']['format']
  if mode == 'json'
    record = JSON.parse(text)
    raise ArgumentError, 'JSON root must be an object' unless record.is_a?(Hash)
    return record
  end
  if mode == 'kv'
    record = {}
    text.scan(/(?:\A|\s)([A-Za-z_][A-Za-z0-9_.-]*)=(?:"([^"]*)"|'([^']*)'|([^\s]+))/) do |key, quoted, single_quoted, bare|
      record[key] = quoted || single_quoted || bare
    end
    raise ArgumentError, 'No key value pairs found' if record.empty?
    return record
  end
  raise ArgumentError, 'Unsupported input format'
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
      parserstudio_assign(target, rule['normalized_name'], parserstudio_coerce(raw, rule))
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
