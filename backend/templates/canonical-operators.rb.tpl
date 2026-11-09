# Executable operator source shared by every generated parser template.
# Canonical classifier contract: parser-studio.operator-semantics.v1

def parserstudio_trim_ascii(value)
  value.gsub(/\A[ \t\n\r\f\v]+|[ \t\n\r\f\v]+\z/, '')
end

def parserstudio_case_transform(value, operation)
  table = @parserstudio_case_map.fetch(operation)
  value.each_char.map { |character| table.fetch(character.ord.to_s(16), character) }.join
end

# Only the official timestamp wire field changes representation. Operators
# consume the same validated ISO text as the browser until this boundary.
def parserstudio_wire_record(record, strict = true)
  output = record.dup
  if output['timestamp'].is_a?(String)
    begin
      canonical = parserstudio_coerce(output['timestamp'], {'data_type'=>'date','time_format'=>'iso8601'})
      output['timestamp'] = (Time.iso8601(canonical).to_r * 1000).floor
    rescue StandardError
      raise ParserstudioFieldError.new('timestamp') if strict
      output.delete('timestamp')
    end
  end
  output
end

class ParserstudioFieldError < StandardError
  attr_reader :field
  def initialize(field)
    @field = field
    super('invalid_mapped_field')
  end
end

def parse(text)
  @parserstudio_partial = nil
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
    # Enrichment is a transaction: an invalid new official field must not
    # escape through the partial-record error path.
    enriched = parserstudio_enrich(JSON.parse(JSON.generate(normalized)))
    parserstudio_verify_proto_pair!(enriched)
    # Ordered enrichment and classification see the same ISO timestamp string
    # as the validated browser preview. Only the final emitted native field
    # requires the canonical epoch-ms integer.
    current_stage = 'classification'
    event_index = parserstudio_classify(enriched)
    current_stage = 'enrichment'
    normalized = parserstudio_wire_record(enriched)
    @parserstudio_partial = normalized
    current_stage = 'classification'
    normalized['stellar_log_index'] = event_index
    normalized['msg_origin'] = {
      'source' => @parser_rule_set['normalization']['msgOriginSource'],
      'category' => @parser_rule_set['normalization']['msgOriginCategory'],
      'class' => @parser_rule_set['normalization']['msgClass']
    }
    event_time = parserstudio_event_time(normalized)
    yield event_time, normalized
  rescue StandardError => e
    # Diagnostics are static codes and schema-controlled field paths. Fields that
    # were already mapped and validated before the failure stay next to them; the
    # field that failed, unmapped source data, raw log text and exception messages
    # are never copied.
    diagnostic = {
      'stellar_log_index' => 'syslog',
      'parser_err_msg' => e.is_a?(ParserstudioFieldError) ? 'MappedFieldError' : e.class.name,
      'parser_err_stage' => current_stage
    }
    diagnostic['parser_err_field'] = e.field if e.is_a?(ParserstudioFieldError)
    kept = @parserstudio_partial.is_a?(Hash) ? @parserstudio_partial : {}
    yield nil, parserstudio_wire_record(kept, false).merge(diagnostic)
  end
end

def parserstudio_lookup(record, path, kind = nil)
  if kind
    # Preserve the historical ambiguous-path failure even for strict selectors.
    parserstudio_lookup(record, path)
    if kind == 'literal_root'
      return record.is_a?(Hash) ? record[path] : nil
    elsif kind == 'nested'
      cursor = record
      path.split('.').each do |piece|
        return nil unless cursor.is_a?(Hash) && cursor.key?(piece)
        cursor = cursor[piece]
      end
      return cursor
    end
    raise ArgumentError, 'Unknown source path kind'
  end
  parts = path.split('.')
  found = []
  walk = nil
  walk = lambda do |current, at|
    next unless current.is_a?(Hash)
    (at...parts.length).each do |last|
      key = parts[at..last].join('.')
      next unless current.key?(key)
      value = current[key]
      if last + 1 == parts.length
        found << value
      else
        walk.call(value, last + 1)
      end
      raise ArgumentError, 'Ambiguous source path' if found.length > 1
    end
  end
  walk.call(record, 0)
  found.first
end

# Serialize structured JSON as JavaScript JSON.stringify does for supported
# JSON scalar values: array-index key ordering and shortest decimal numbers.
# Never execute input as code or mutate original source hashes.
def parserstudio_json_number(value)
  return value.to_s if value.is_a?(Integer)
  raise ArgumentError, 'Nonfinite JSON number' unless value.is_a?(Float) && value.finite?
  return '0' if value.zero?
  str = value.to_s
  # Ruby commonly writes 1.0e-06 whereas JSON.stringify writes 0.000001.
  if (value.abs >= 0.000001 && value.abs < 1.0e21)
    if (match = /\A(-?)(\d+)(?:\.(\d+))?e([+-]?\d+)\z/.match(str))
      digits = match[2] + (match[3] || '')
      position = match[2].length + match[4].to_i
      expanded = if position <= 0
        '0.' + '0' * -position + digits
      elsif position >= digits.length
        digits + '0' * (position - digits.length)
      else
        digits[0...position] + '.' + digits[position..-1]
      end
      return match[1] + expanded.sub(/(\.\d*?)0+\z/, '\\1').sub(/\.\z/, '')
    end
    return str.sub(/\.0\z/, '')
  end
  if (match = /\A(-?)(\d+)(?:\.(\d+))?e([+-]?\d+)\z/.match(str))
    fraction = (match[3] || '').sub(/0+\z/, '')
    exponent = match[4].to_i
    return match[1] + match[2] + (fraction.empty? ? '' : '.' + fraction) +
      'e' + (exponent >= 0 ? '+' : '') + exponent.to_s
  end
  str.sub(/\.0\z/, '')
end

def parserstudio_json_stringify(value)
  case value
  when Hash
    keys = value.keys
    indexes = keys.select do |key|
      key.is_a?(String) && key.match?(/\A(?:0|[1-9]\d*)\z/) &&
        key.length <= 10 && key.to_i < 4294967295
    end.sort_by(&:to_i)
    ordered = indexes + keys.reject { |key| indexes.include?(key) }
    '{' + ordered.map { |key|
      JSON.generate(key) + ':' + parserstudio_json_stringify(value[key])
    }.join(',') + '}'
  when Array
    '[' + value.map { |item| parserstudio_json_stringify(item) }.join(',') + ']'
  when Float, Integer
    parserstudio_json_number(value)
  else
    JSON.generate(value)
  end
end

def parserstudio_coerce(value, rule)
  type = rule['data_type']
  raise ArgumentError, 'Compound value cannot be a scalar' if
    type != 'string' && (value.is_a?(Hash) || value.is_a?(Array))
  str = value.is_a?(String) ? parserstudio_trim_ascii(value) : value.to_s
  raise ArgumentError, 'Missing mapped value' if str.empty?
  case type
  when 'string'
    # Match the browser's JSON.stringify for object/array source values.
    # JSON numeric tokens use JS Number string semantics in the browser;
    # Ruby JSON.parse may preserve integral 6.0/6e0 as Float.
    if value.is_a?(Hash) || value.is_a?(Array)
      parserstudio_json_stringify(value)
    elsif value.is_a?(Integer) || value.is_a?(Float)
      parserstudio_json_number(value)
    else
      value.to_s
    end
  when 'integer', 'port'
    # Ruby JSON.parse preserves 6.0/6e0 as Float while JS JSON.parse sees 6.
    # Convert only EXACTLY integral, safe Float values; no rounding.
    str = value.to_i.to_s if value.is_a?(Float) && value.finite? &&
      value == value.to_i && value.abs <= 9007199254740991
    # A signed port is not in the browser's reviewed grammar; integers
    # permit a leading minus only. Spaces are trimmed consistently.
    integer_pattern = type == 'port' ? /\A\d+\z/ : /\A-?\d+\z/
    raise ArgumentError, 'Invalid integer' unless str.match?(integer_pattern)
    number = Integer(str, 10)
    raise ArgumentError, 'Unsafe integer' if number.abs > 9007199254740991
    raise ArgumentError, 'Invalid port' if type == 'port' && (number < 0 || number > 65535)
    number
  when 'boolean'
    str = value.to_i.to_s if value.is_a?(Float) && value.finite? &&
      value == value.to_i && value.abs <= 9007199254740991
    return true if value == true || str.downcase == 'true' || str == '1'
    return false if value == false || str.downcase == 'false' || str == '0'
    raise ArgumentError, 'Invalid boolean'
  when 'ip'
    # IPAddr accepts CIDR masks and IPv6 interface zones; Stellar's srcip/dstip
    # need host IP literals, with neither an attached prefix nor a zone.
    raise ArgumentError, 'Not a host IP literal' if str.include?('/') || str.include?('%')
    raise ArgumentError, 'Not a literal IP alphabet' unless str.match?(/\A[0-9a-fA-F:.]+\z/)
    IPAddr.new(str)
    str
  when 'date'
    raise ArgumentError, 'Unsupported date policy' unless rule['time_format'] == 'iso8601'
    raise ArgumentError, 'Timestamp must contain an explicit timezone' unless str.match?(/(?:Z|[+-]\d{2}:\d{2})\z/)
    raise ArgumentError, 'Invalid ISO timestamp clock or timezone' unless
      str.match?(/\A\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/)
    date_match = /\A(\d{4})-(\d{2})-(\d{2})T/.match(str)
    raise ArgumentError, 'Invalid ISO calendar date' unless date_match &&
      date_match[1].to_i > 0 &&
      Date.valid_date?(date_match[1].to_i, date_match[2].to_i, date_match[3].to_i, Date::GREGORIAN)
    instant = Time.iso8601(str).utc
    raise ArgumentError, 'UTC timestamp outside supported calendar' unless instant.year.between?(1,9999)
    instant.iso8601(3)
  else
    raise ArgumentError, 'Unsupported type'
  end
end

# Fixed Stellar Cyber 7.0 scalar semantics for reviewed official fields only.
# Preserve vendor-local mappings; never turn invalid values into accepted data.
def parserstudio_stellar7_value_valid?(name, raw, converted)
  kind = (@parserstudio_official_types || {})[name]
  basic = case kind
  when 'string' then converted.is_a?(String)
  when 'integer' then converted.is_a?(Integer) && converted.abs <= 9007199254740991
  when 'port' then converted.is_a?(Integer) && converted.between?(0,65535)
  when 'number' then converted.is_a?(Numeric) && converted.finite?
  when 'boolean' then converted == true || converted == false
  when 'timestamp'
    begin
      converted.is_a?(String) && !!parserstudio_coerce(converted, {'data_type'=>'date','time_format'=>'iso8601'})
    rescue StandardError
      false
    end
  when 'ip'
    begin
      converted.is_a?(String) && converted.match?(/\A[0-9a-fA-F:.]+\z/) &&
        parserstudio_coerce(converted, {'data_type'=>'ip'}) == converted
    rescue StandardError
      false
    end
  else kind.nil?
  end
  return false unless basic
  leaf = name.to_s.split('.').last
  widths = {'md5' => 32, 'sha1' => 40, 'sha256' => 64}
  if widths.key?(leaf)
    return raw.is_a?(String) && raw.match?(Regexp.new("\\A[0-9a-fA-F]{#{widths[leaf]}}\\z"))
  end
  return raw.is_a?(String) if name == 'action'
  if name == 'proto'
    return converted.is_a?(Integer) && converted.between?(0, 255)
  end
  if name == 'proto_name'
    return raw.is_a?(String) && %w[tcp udp icmp igmp].include?(parserstudio_trim_ascii(raw).downcase)
  end

  if name == 'srcport' || name == 'dstport'
    return converted.is_a?(Integer) && converted.between?(0, 65535)
  end
  if name == 'severity'
    return converted.is_a?(Integer) && converted.between?(0, 100)
  end
  true
end

# Validate the FINAL value of every enriched Stellar 7.0 scalar field.
# The allowlist is compiled from the pinned 7.0 mappable-field catalog.
# Unknown/vendor-local extension fields retain their original flexible behavior.
def parserstudio_prepare_enriched_value(target, value)
  type = @parserstudio_official_types[target]
  return value unless type
  converted = value
  case type
  when 'string'
    raise ArgumentError, 'Official string must be text' unless value.is_a?(String)
  when 'integer', 'port'
    raise ArgumentError, 'Official integer must be safe and integral' unless
      value.is_a?(Integer) && value.abs <= 9007199254740991
    raise ArgumentError, 'Official port outside range' if type == 'port' &&
      !value.between?(0,65535)
  when 'number'
    raise ArgumentError, 'Official number must be finite' unless
      value.is_a?(Numeric) && value.finite?
  when 'boolean'
    raise ArgumentError, 'Official boolean must be boolean' unless
      value == true || value == false
  when 'ip'
    raise ArgumentError, 'Official IP must be a host literal' unless value.is_a?(String)
    converted = parserstudio_coerce(value, {'data_type'=>'ip'})
    raise ArgumentError, 'Copy must preserve the reviewed IP value' unless converted == value
  when 'timestamp'
    if value.is_a?(String)
      converted = parserstudio_coerce(value, {
        'data_type'=>'date', 'time_format'=>'iso8601'})
    else
      raise ArgumentError, 'Official timestamp must be epoch ms or ISO string' unless
        value.is_a?(Integer) && value.abs <= 9007199254740991
    end
  else
    raise ArgumentError, 'Unsupported enriched official type'
  end
  raise ArgumentError, 'Invalid enriched official field value' unless
    parserstudio_stellar7_value_valid?(target, value, converted)
  # Preserve the validated ISO text during ordered enrichment. Downstream
  # copy/uppercase/merge rules and classification are authored against the
  # original string (as in the browser preview). Convert to epoch milliseconds
  # only after these steps have completed.
  return value if type == 'timestamp' && value.is_a?(String)
  converted
end

# An IP protocol number and its L4 name may not contradict each other.
def parserstudio_verify_proto_pair!(normalized)
  number = normalized['proto']
  name = normalized['proto_name']
  return if number.nil? || name.nil?
  expected = {'tcp'=>6, 'udp'=>17, 'icmp'=>[1,58], 'igmp'=>2}[parserstudio_trim_ascii(name.to_s).downcase]
  valid = expected.is_a?(Array) ? expected.include?(number) : expected == number
  raise ParserstudioFieldError.new('proto_name') unless valid
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

def parserstudio_when_applies?(original, rule)
  predicate = rule['when']
  return true unless predicate
  value = parserstudio_lookup(original, predicate['sourcePath'])
  return false if value.nil? || !(value.is_a?(String) || value.is_a?(Numeric))
  # JavaScript String(6.0) is "6" after JSON decoding. Match its numeric
  # representation so a Ruby Float with integral value cannot drift.
  token = value.is_a?(Numeric) ? parserstudio_json_number(value) : value
  predicate['values'].include?(token)
rescue ArgumentError
  # Ambiguous predicate source paths are untrusted. Omit only this mapping,
  # preserving unrelated fields and the original vendor event.
  false
end

def parserstudio_event_profile(original)
  config = @parser_rule_set['normalization']['eventProfiles']
  return nil if config.nil?
  key = config['discriminator']
  value = parserstudio_lookup(original, key)
  raise ParserstudioFieldError.new(key) unless value.is_a?(String)
  profiles = config['variants'].select { |profile| profile['equals'] == value }
  raise ParserstudioFieldError.new(key) unless profiles.length == 1
  profiles.first
rescue ArgumentError
  raise ParserstudioFieldError.new(key)
end

# Lookup, conversion and assignment share one field-scoped failure boundary.
# Continue every independent mapping, retaining only validated output values.
def parserstudio_apply_field_maps(original, normalized, maps, ignored)
  first_failed = nil
  ['topFields', 'nsFields', 'vendorFields'].each do |section|
    maps[section].each do |source, rule|
      begin
        next unless parserstudio_when_applies?(original, rule)
        raw = parserstudio_lookup(original, source, rule['source_path_kind'])
        next if raw.nil? || (raw.is_a?(String) && ignored.include?(raw))
        converted = parserstudio_coerce(raw, rule)
        if section != 'vendorFields' && !parserstudio_stellar7_value_valid?(rule['normalized_name'], raw, converted)
          raise ArgumentError, 'Invalid official Stellar field value'
        end
        target = normalized
        if section == 'vendorFields'
          namespace = @parser_rule_set['vendor']
          target[namespace] ||= {}
          target = target[namespace]
        end
        parserstudio_assign(target, rule['normalized_name'], converted)
      rescue StandardError
        first_failed ||= source
      end
    end
  end
  first_failed
end

def parserstudio_normalize(original)
  normalized = {}
  @parserstudio_partial = normalized
  ignored = @parser_rule_set['normalization']['ignoreValues']
  first_failed = nil
  profile = nil
  begin
    profile = parserstudio_event_profile(original)
  rescue ParserstudioFieldError => error
    first_failed = error.field
  end
  failure = parserstudio_apply_field_maps(original, normalized,
    @parser_rule_set['normalization'], ignored)
  first_failed ||= failure
  if profile
    failure = parserstudio_apply_field_maps(original, normalized, profile, ignored)
    first_failed ||= failure
    normalized['parserstudio_event_family'] = profile['name']
  end
  hops = original['__parserstudio_forwarder_hops']
  normalized['parserstudio_transport'] = {'forwarder_hops'=>hops} if hops && !hops.empty?
  raise ParserstudioFieldError.new(first_failed) if first_failed
  parserstudio_verify_proto_pair!(normalized)
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
          value = parserstudio_case_transform(value, operation)
        end
      when 'split_field'
        value = parserstudio_lookup(normalized, rule['source'])
        delimiter = rule['delimiter']
        targets = rule['targets']
        raise ArgumentError, 'Split enrichment requires string input' unless value.is_a?(String)
        raise ArgumentError, 'Split enrichment delimiter invalid' unless delimiter.is_a?(String) && delimiter.length.between?(1, 8)
        raise ArgumentError, 'Split enrichment targets invalid' unless targets.is_a?(Array) && targets.length.between?(2, 8)
        parts = value.split(Regexp.new(Regexp.escape(delimiter)), -1)
        raise ArgumentError, 'Split enrichment field count mismatch' unless parts.length == targets.length
        targets.each_with_index do |target, index|
          parserstudio_assign(normalized, target,
            parserstudio_prepare_enriched_value(target, parts[index]))
        end
        next
      when 'merge_fields'
        delimiter = rule['delimiter']
        sources = rule['sources']
        raise ArgumentError, 'Merge enrichment delimiter invalid' unless delimiter.is_a?(String) && delimiter.length.between?(1, 8)
        raise ArgumentError, 'Merge enrichment sources invalid' unless sources.is_a?(Array) && sources.length.between?(2, 8)
        values = sources.map do |source|
          item = parserstudio_lookup(normalized, source)
          raise ArgumentError, 'Merge enrichment source absent' unless item.is_a?(String)
          item
        end
        value = values.join(delimiter)
      else
        raise ArgumentError, 'Unknown enrichment operator'
      end
      parserstudio_assign(normalized, rule['target'],
        parserstudio_prepare_enriched_value(rule['target'], value))
    rescue StandardError
      raise ParserstudioFieldError.new(field)
    end
  end
  normalized
end

# Canonical classifier contract: parser-studio.operator-semantics.v1
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
