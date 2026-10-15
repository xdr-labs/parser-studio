# Parser Studio bounded Generic Structural compiler helper.
# Emitted only for generic_structural projects; no arbitrary user code executes.

def parserstudio_generic_structural(text)
  result = parserstudio_generic_short_rfc5424_json(text)
  return result if result
  result = parserstudio_generic_asa(text)
  return result if result
  result = parserstudio_generic_junos_rfc5424_sd(text)
  return result if result
  result = parserstudio_generic_bracket_colon_kv(text)
  return result if result
  result = parserstudio_generic_comma_kv(text)
  return result if result
  result = parserstudio_generic_space_kv(text)
  return result if result
  raise ArgumentError, 'Unsupported generic structural event'
end

def parserstudio_generic_short_rfc5424_json(text)
  match = /\A<(\d{1,3})>(1) (\S{1,64}) ([!-~]{1,255}) (\{.*\})\z/.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191)
  return nil unless match[3].match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/)
  begin
    Time.iso8601(match[3])
    body = parserstudio_json_object(match[5])
  rescue StandardError
    return nil
  end
  {
    'syslog' => {
      'pri' => match[1], 'version' => match[2],
      'timestamp' => match[3], 'hostname' => match[4]
    },
    'body' => body
  }
end

def parserstudio_split_escaped(text, delimiter)
  parts = []
  token = +''
  quote = nil
  escaped = false
  text.each_char do |char|
    if escaped
      token << char
      escaped = false
    elsif char == '\\'
      token << char
      escaped = true
    elsif quote
      token << char
      quote = nil if char == quote
    elsif char == '"' || char == "'"
      quote = char
      token << char
    elsif char == delimiter
      parts << token
      token = +''
    else
      token << char
    end
  end
  return nil if escaped || quote
  parts << token
  parts
end

def parserstudio_generic_junos_rfc5424_sd(text)
  match = /\A<(\d{1,3})>(1) (\S+) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[junos@[A-Za-z0-9.:-]{1,64}(?: [^\]]*)?\])\z/.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191)
  return nil unless match[3].match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/)
  begin
    Time.iso8601(match[3])
  rescue StandardError
    return nil
  end
  structured = match[8]
  return nil if structured.bytesize > 8192
  inner = structured[1...-1]
  head = /\Ajunos@[A-Za-z0-9.:-]{1,64}/.match(inner)
  return nil unless head
  pos = head[0].length
  fields = {}
  while pos < inner.length
    return nil unless inner[pos] == ' '
    pos += 1
    key_match = /\A[A-Za-z_][A-Za-z0-9_-]{0,63}/.match(inner[pos..-1].to_s)
    return nil unless key_match
    key = key_match[0]
    pos += key.length
    return nil unless inner[pos, 2] == '="'
    pos += 2
    value = +''
    closed = false
    while pos < inner.length
      char = inner[pos]
      if char == '"'
        closed = true
        pos += 1
        break
      elsif char == '\\'
        following = inner[pos + 1]
        return nil unless ['"', '\\', ']'].include?(following)
        value << following
        pos += 2
      else
        return nil if char.ord < 32 || char.ord == 127
        value << char
        pos += 1
      end
    end
    return nil unless closed
    safe = key.tr('-', '_')
    return nil if fields.key?(safe)
    fields[safe] = value
    return nil if fields.length > 64
  end
  return nil if fields.empty?
  {
    'syslog' => {
      'pri' => match[1], 'version' => match[2], 'timestamp' => match[3],
      'hostname' => match[4], 'appname' => match[5], 'procid' => match[6],
      'msgid' => match[7], 'structured_data_raw' => structured
    },
    'junos_sd' => fields
  }
end

def parserstudio_generic_bracket_colon_kv(text)
  match = /\A<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) /.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191) && match[2] == '1'
  values = [match[3], match[4], match[5], match[6], match[7]]
  limits = [64, 255, 48, 128, 32]
  return nil unless values.each_with_index.all? { |value, index|
    value.bytesize <= limits[index] && value.match?(/\A[!-~]+\z/)
  }
  body_text = text[match.end(0)..-1].to_s
  return nil unless body_text.start_with?('[') && body_text.end_with?(']')
  body = {}
  pos = 1
  count = 0
  while pos < body_text.length - 1
    pos += 1 while pos < body_text.length - 1 && [' ', "\t"].include?(body_text[pos])
    break if pos == body_text.length - 1
    key_match = /\A[A-Za-z_][A-Za-z0-9_.:-]{0,127}/.match(body_text[pos..-1].to_s)
    return nil unless key_match
    key = key_match[0]
    return nil if ['__proto__', 'prototype', 'constructor'].include?(key)
    pos += key.length
    return nil unless body_text[pos] == ':'
    pos += 1
    return nil unless body_text[pos] == '"'
    pos += 1
    value = +''
    closed = false
    while pos < body_text.length - 1
      char = body_text[pos]
      if char == '\\'
        return nil if pos + 1 >= body_text.length - 1
        following = body_text[pos + 1]
        value << (['"', '\\'].include?(following) ? following : '\\' + following)
        pos += 2
      elsif char == '"'
        closed = true
        pos += 1
        break
      else
        value << char
        pos += 1
      end
    end
    return nil unless closed
    pos += 1 while pos < body_text.length - 1 && [' ', "\t"].include?(body_text[pos])
    return nil if pos < body_text.length - 1 && body_text[pos] != ';'
    pos += 1 if pos < body_text.length - 1
    previous = body[key]
    body[key] = previous.nil? ? value : previous.is_a?(Array) ? previous + [value] : [previous, value]
    count += 1
    return nil if count > 1024
  end
  return nil if count < 1
  {'syslog'=>{'pri'=>match[1],'version'=>match[2],'timestamp'=>match[3],'hostname'=>match[4],
    'appname'=>match[5],'procid'=>match[6],'msgid'=>match[7]},'body'=>body}
end

def parserstudio_generic_comma_kv(text)
  parts = parserstudio_split_escaped(text, ',')
  return nil unless parts && parts.length >= 3
  prefix = parts[0].to_s.strip
  syslog = {}
  if (pri = /\A<(\d{1,3})>/.match(prefix))
    value = Integer(pri[1], 10)
    return nil unless value.between?(0, 191)
    syslog['pri'] = pri[1]
    prefix = prefix[pri.end(0)..-1].to_s.strip
  end
  return nil unless prefix.match?(/(?:\A|[ \t])\d{4}-\d{2}-\d{2}(?:[ \t]|\z)/)
  tokens = prefix.split(/[ \t]+/).map do |value|
    value.length > 1 && [':', ','].include?(value[-1]) ? value[0...-1] : value
  end
  return nil unless tokens.length.between?(8, 64) &&
    tokens.all? { |value| value.bytesize.between?(1, 256) }

  fields = {}
  parts.drop(1).each do |segment|
    stripped = segment.strip
    next if stripped.empty?
    eq = stripped.index('=')
    return nil unless eq && eq > 0
    key = stripped[0...eq].strip
    return nil unless key.match?(/\A[A-Za-z_][A-Za-z0-9_.#\/-]{0,127}\z/) && !fields.key?(key)
    value = stripped[(eq + 1)..-1].to_s.strip
    if value.length >= 2 && ((value.start_with?('"') && value.end_with?('"')) ||
       (value.start_with?("'") && value.end_with?("'")))
      value = value[1...-1]
    elsif value.start_with?('"', "'") || value.end_with?('"', "'")
      return nil
    end
    fields[key] = value
  end
  return nil unless fields.length >= 2
  generic = {'mode' => 'comma_kv', 'kv' => fields}
  tokens.each_with_index { |value, index| generic[format('prefix_%03d', index + 1)] = value }
  result = {'generic' => generic}
  result['syslog'] = syslog unless syslog.empty?
  result
end

def parserstudio_generic_space_kv(text)
  return nil if text.bytesize > 8192
  pattern = /(?:\A|[ \t])([A-Za-z_][A-Za-z0-9_.-]{0,63})=/
  entries = []
  offset = 0
  while (match = pattern.match(text, offset))
    start = match.begin(0)
    start += 1 if [' ', "\t"].include?(text[start])
    entries << {'key'=>match[1], 'start'=>start, 'value_start'=>match.end(0)}
    return nil if entries.length > 100
    offset = match.end(0)
  end
  return nil if entries.length < 5
  prefix = text[0...entries[0]['start']].to_s.strip
  tokens = prefix.empty? ? [] : prefix.split(/[ \t]+/).map do |value|
    value.length > 1 && [':', ','].include?(value[-1]) ? value[0...-1] : value
  end
  return nil if !prefix.empty? && (!tokens.length.between?(2, 16) ||
    tokens.any? { |value| value.empty? || value.bytesize > 256 })
  fields = {}
  atoms = {}
  entries.each_with_index do |entry, index|
    key = entry['key']
    return nil if fields.key?(key)
    finish = index + 1 < entries.length ? entries[index + 1]['start'] : text.length
    value = text[entry['value_start']...finish].to_s.strip
    quoted = value.length >= 2 &&
      ((value.start_with?('"') && value.end_with?('"')) ||
       (value.start_with?("'") && value.end_with?("'")))
    if quoted
      value = value[1...-1]
    elsif value.start_with?('"', "'") || value.end_with?('"', "'")
      return nil
    end
    return nil if value.bytesize > 512 || value.match?(/[\x00-\x1f\x7f]/)
    fields[key] = value
    if !quoted && value.match?(/[ \t]/)
      first = value.split(/[ \t]+/)[0]
      atoms[key.tr('-', '_') + '_001'] = first
    end
  end
  generic = {'mode'=>'space_kv', 'source_raw'=>text, 'kv'=>fields}
  tokens.each_with_index { |value, index| generic[format('prefix_%03d', index + 1)] = value }
  generic['atoms'] = atoms unless atoms.empty?
  {'generic'=>generic}
end

def parserstudio_generic_asa(text)
  id_pattern = /%(ASA|FTD)-(\d)-(\d{6}):[ \t]*/
  id = id_pattern.match(text)
  return nil unless id
  return nil if id_pattern.match(text, id.end(0))
  severity = Integer(id[2], 10)
  return nil unless severity.between?(0, 7)
  body = text[id.end(0)..-1].to_s
  built = /\A(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)\z/.match(body)
  deny = /\A(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})\z/.match(body)
  full = built || deny
  return nil unless full
  fields = {'product' => id[1], 'severity' => id[2], 'message_id' => id[3]}
  full.names.each do |name|
    value = full[name]
    fields[name] = value unless value.nil?
  end
  %w[src_port dst_port mapped_src_port mapped_dst_port].each do |name|
    next unless fields.key?(name)
    return nil unless Integer(fields[name], 10).between?(0, 65_535)
  end

  syslog = {'app_tag' => "%#{id[1]}-#{id[2]}-#{id[3]}"}
  prefix = text[0...id.begin(0)]
  unless prefix.empty?
    header = /\A([A-Z][a-z]{2})[ ]+(\d{1,2})[ ]+(\d{2}):(\d{2}):(\d{2})[ ]+([!-~]{1,255})[ ]*\z/.match(prefix)
    return nil unless header
    month_days = {'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,
      'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}
    day = Integer(header[2], 10)
    hour = Integer(header[3], 10)
    minute = Integer(header[4], 10)
    second = Integer(header[5], 10)
    return nil unless month_days[header[1]] && day.between?(1, month_days[header[1]]) &&
      hour.between?(0, 23) && minute.between?(0, 59) && second.between?(0, 59)
    syslog['month'] = header[1]
    syslog['day'] = header[2]
    syslog['time'] = "#{header[3]}:#{header[4]}:#{header[5]}"
    syslog['hostname'] = header[6]
  end
  {'syslog' => syslog, 'asa' => fields}
end
