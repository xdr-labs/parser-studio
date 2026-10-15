# Parser Studio bounded Generic Structural compiler helper.
# Emitted only for generic_structural projects; no arbitrary user code executes.

def parserstudio_generic_structural(text)
  result = parserstudio_generic_short_rfc5424_json(text)
  return result if result
  result = parserstudio_generic_asa(text)
  return result if result
  result = parserstudio_generic_comma_kv(text)
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
