# Parser Studio bounded Generic Structural compiler helper.
# Emitted only for generic_structural projects; no arbitrary user code executes.

def parserstudio_generic_structural(text)
  result = parserstudio_generic_short_rfc5424_structured(text)
  return result if result
  result = parserstudio_generic_short_rfc5424_json(text)
  return result if result
  result = parserstudio_generic_prefixed_json(text)
  return result if result
  result = parserstudio_generic_iso_pri_mixed(text)
  return result if result
  result = parserstudio_generic_iso_pri_positional(text)
  return result if result
  result = parserstudio_generic_asa(text)
  return result if result
  result = parserstudio_generic_watchguard(text)
  return result if result
  result = parserstudio_generic_watchguard_message(text)
  return result if result
  result = parserstudio_generic_dual_timestamp_session(text)
  return result if result
  result = parserstudio_generic_bsd_bracket_pid_message(text)
  return result if result
  result = parserstudio_generic_juniper_legacy(text)
  return result if result
  result = parserstudio_generic_junos_rfc5424_sd(text)
  return result if result
  result = parserstudio_generic_bracket_colon_kv(text)
  return result if result
  result = parserstudio_generic_rfc3164_delimited_comma_kv(text)
  return result if result
  result = parserstudio_generic_rfc3164_positional_csv(text)
  return result if result
  result = parserstudio_generic_pri_space_kv(text)
  return result if result
  result = parserstudio_generic_syslog_envelope_structured(text)
  return result if result
  result = parserstudio_generic_comma_kv(text)
  return result if result
  result = parserstudio_generic_delimited_comma_kv(text)
  return result if result
  result = parserstudio_generic_space_kv(text)
  return result if result
  raise ArgumentError, 'Unsupported generic structural event'
end

def parserstudio_generic_short_rfc5424_structured(text)
  match = /\A<(\d{1,3})>(1) (\S{1,64}) ([!-~]{1,255}) ((?:CEF:0\|.*|LEEF:(?:1\.0|2\.0)\|.*))\z/m.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191)
  return nil unless match[3].match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/)
  begin
    Time.iso8601(match[3])
    body = match[5].start_with?('CEF:') ? parserstudio_cef(match[5]) : parserstudio_leef(match[5])
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

def parserstudio_generic_prefixed_json(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A([A-Za-z0-9_.:\/-]{1,64})[ \t]+(\{.*\})\z/.match(text)
  return nil unless match
  begin
    body = JSON.parse(match[2])
  rescue JSON::ParserError
    return nil
  end
  return nil unless body.is_a?(Hash)
  {
    'generic' => {'mode'=>'prefixed_json', 'prefix'=>match[1], 'source_raw'=>text},
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

def parserstudio_generic_source_key_safe(key)
  !['__proto__', 'constructor', 'prototype'].include?(key)
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
    return nil unless parserstudio_generic_source_key_safe(key) && parserstudio_generic_source_key_safe(safe)
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

def parserstudio_generic_structural_timestamp_valid(value)
  candidate = value.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\z/) ? value :
    value.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\z/) ? value + 'Z' : nil
  return false unless candidate
  begin
    parsed = Time.iso8601(candidate)
    parsed.year.between?(1, 9999)
  rescue StandardError
    false
  end
end

def parserstudio_generic_bracket_colon_kv(text)
  match = /\A<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) /.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191) && match[2] == '1'
  return nil unless parserstudio_generic_structural_timestamp_valid(match[3])
  values = [match[3], match[4], match[5], match[6], match[7]]
  limits = [64, 255, 48, 128, 32]
  return nil unless values.each_with_index.all? { |value, index|
    value.bytesize <= limits[index] && value.match?(/\A[!-~]+\z/)
  }
  body_text = text[match.end(0)..-1].to_s.sub(/[ \t]+\z/, '')
  return nil unless body_text.start_with?('[') && body_text.end_with?(']')
  body = {}
  pos = 1
  count = 0
  while pos < body_text.length - 1
    pos += 1 while pos < body_text.length - 1 && [' ', "\t"].include?(body_text[pos])
    break if pos == body_text.length - 1
    rest = body_text[pos..-1].to_s
    delimiter = /:\s*"/.match(rest)
    return nil unless delimiter && delimiter.begin(0) > 0
    key = rest[0...delimiter.begin(0)].strip
    return nil unless key.match?(/\A[A-Za-z_][A-Za-z0-9_.:#-]{0,127}\z/) &&
      parserstudio_generic_source_key_safe(key)
    pos += delimiter.end(0)
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
    return nil unless key.match?(/\A[A-Za-z_][A-Za-z0-9_.#\/-]{0,127}\z/) && parserstudio_generic_source_key_safe(key)
    value = stripped[(eq + 1)..-1].to_s.strip
    if value.length >= 2 && ((value.start_with?('"') && value.end_with?('"')) ||
       (value.start_with?("'") && value.end_with?("'")))
      value = value[1...-1]
    elsif value.start_with?('"', "'") || value.end_with?('"', "'")
      return nil
    end
    previous = fields[key]
    fields[key] = previous.nil? ? value : previous.is_a?(Array) ? previous + [value] : [previous, value]
  end
  return nil unless fields.length >= 2
  generic = {'mode' => 'comma_kv', 'kv' => fields}
  tokens.each_with_index { |value, index| generic[format('prefix_%03d', index + 1)] = value }
  result = {'generic' => generic}
  result['syslog'] = syslog unless syslog.empty?
  result
end

def parserstudio_generic_space_kv_entries(text)
  entries = []
  quote = nil
  escaped = false
  pos = 0
  while pos < text.length
    char = text[pos]
    if quote
      if escaped
        escaped = false
      elsif char == '\\'
        escaped = true
      elsif char == quote
        quote = nil
      end
      pos += 1
      next
    end
    if pos == 0 || [' ', "\t"].include?(text[pos - 1])
      match = /\A([A-Za-z_][A-Za-z0-9_.-]{0,63})=/.match(text[pos..-1].to_s)
      if match
        entries << {'key'=>match[1], 'start'=>pos, 'value_start'=>pos + match[0].length}
        return nil if entries.length > 100
      end
    end
    quote = char if ['"', "'"].include?(char)
    pos += 1
  end
  return nil if quote || escaped
  entries
end

def parserstudio_generic_space_kv(text)
  return nil if text.bytesize > 8192
  entries = parserstudio_generic_space_kv_entries(text)
  return nil unless entries
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
    return nil unless parserstudio_generic_source_key_safe(key)
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
      pieces = value.split(/[ \t]+/).reject(&:empty?)
      return nil if pieces.length > 32
      pieces.each_with_index do |piece, piece_index|
        return nil if piece.bytesize > 256
        safe = key.tr('-', '_') + format('_%03d', piece_index + 1)
        return nil if atoms.key?(safe)
        atoms[safe] = piece
        return nil if atoms.length > 100
      end
    end
  end
  generic = {'mode'=>'space_kv', 'source_raw'=>text, 'kv'=>fields}
  tokens.each_with_index { |value, index| generic[format('prefix_%03d', index + 1)] = value }
  generic['atoms'] = atoms unless atoms.empty?
  {'generic'=>generic}
end

def parserstudio_generic_pri_space_kv(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A<(\d{1,3})>(.+)\z/.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191)
  parsed = parserstudio_generic_space_kv(match[2])
  return nil unless parsed.is_a?(Hash) && parsed['generic'].is_a?(Hash)
  generic = parsed['generic'].dup
  generic['source_raw'] = text
  {'syslog'=>{'pri'=>match[1]}, 'generic'=>generic}
rescue StandardError
  nil
end

def parserstudio_generic_valid_bsd_clock(month, day_text, time)
  days = {'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,
          'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}
  return false unless days.key?(month)
  day = Integer(day_text, 10)
  hour, minute, second = time.split(':').map { |value| Integer(value, 10) }
  day.between?(1, days[month]) && hour.between?(0, 23) &&
    minute.between?(0, 59) && second.between?(0, 59)
rescue StandardError
  false
end

def parserstudio_generic_profile_tokens(text, start)
  return nil unless start.between?(0, text.length)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  tokens = []
  groups = []
  kv = {}
  pos = start
  count = 0
  while pos < text.length
    pos += 1 while pos < text.length && text[pos].match?(/\s/)
    break if pos == text.length
    count += 1
    return nil if count > 100
    if ['"', "'"].include?(text[pos])
      quote = text[pos]
      cursor = pos + 1
      begin_value = cursor
      closed = false
      while cursor < text.length
        if text[cursor] == '\\' && cursor + 1 < text.length
          cursor += 2
          next
        end
        if text[cursor] == quote
          closed = true
          break
        end
        cursor += 1
      end
      return nil unless closed
      tokens << text[begin_value...cursor]
      cursor += 1
      cursor += 1 if cursor < text.length && '.,:!?'.include?(text[cursor])
      return nil if cursor < text.length && !text[cursor].match?(/\s/) && ![',',';'].include?(text[cursor])
      pos = cursor
      pos += 1 if pos < text.length && [',',';'].include?(text[pos])
      next
    end
    if text[pos] == '('
      finish = text.index(')', pos + 1)
      return nil unless finish
      return nil if finish + 1 < text.length && !text[finish + 1].match?(/\s/)
      groups << text[(pos + 1)...finish]
      pos = finish + 1
      next
    end
    key_match = /\A([A-Za-z_][A-Za-z0-9_.-]{0,127})=/.match(text[pos..-1].to_s)
    if key_match
      key = key_match[1]
      return nil unless parserstudio_generic_source_key_safe(key)
      cursor = pos + key_match[0].length
      start_value = cursor
      finish = cursor
      quote = text[cursor]
      if ['"', "'"].include?(quote)
        cursor += 1
        start_value = cursor
        closed = false
        while cursor < text.length
          if text[cursor] == '\\' && cursor + 1 < text.length
            cursor += 2
            next
          end
          if text[cursor] == quote
            finish = cursor
            cursor += 1
            closed = true
            break
          end
          cursor += 1
        end
        return nil unless closed
        return nil if cursor < text.length && !text[cursor].match?(/\s/)
      else
        cursor += 1 while cursor < text.length && !text[cursor].match?(/\s/)
        finish = cursor
      end
      value = text[start_value...finish].to_s
      previous = kv[key]
      kv[key] = previous.nil? ? value : previous.is_a?(Array) ? previous + [value] : [previous, value]
      pos = cursor
      next
    end
    begin_token = pos
    pos += 1 while pos < text.length && !text[pos].match?(/\s/)
    tokens << text[begin_token...pos]
  end
  {'tokens'=>tokens, 'kv'=>kv, 'groups'=>groups}
end

def parserstudio_generic_ip_token(value)
  IPAddr.new(value)
  true
rescue StandardError
  false
end

def parserstudio_generic_iso_pri_mixed(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A<(\d{1,3})>(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{4}|[+-]\d{2}:\d{2}) +/.match(text)
  return nil unless match
  priority = Integer(match[1], 10)
  return nil unless priority.between?(0, 191)
  zone = match[4]
  normalized_zone = zone == 'Z' ? 'Z' : (zone.include?(':') ? zone : zone[0,3] + ':' + zone[3,2])
  begin
    Time.iso8601("#{match[2]}T#{match[3]}#{normalized_zone}")
  rescue StandardError
    return nil
  end
  body = parserstudio_generic_profile_tokens(text, match.end(0))
  return nil unless body && body['tokens'].length >= 16
  values = body['tokens'].dup
  body['kv'].each_value do |value|
    value.is_a?(Array) ? values.concat(value.map(&:to_s)) : values << value.to_s
  end
  return nil if values.count { |value| parserstudio_generic_ip_token(value) } < 2
  {
    'syslog'=>{'pri'=>match[1],'date'=>match[2],'time'=>match[3],'timezone'=>match[4]},
    'generic'=>body
  }
rescue StandardError
  nil
end

def parserstudio_generic_iso_pri_positional(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A<(\d{1,3})>(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{4}|[+-]\d{2}:\d{2}) +/.match(text)
  return nil unless match
  pri = Integer(match[1], 10)
  return nil unless pri.between?(0, 191)
  normalized_zone = match[4] == 'Z' ? 'Z' :
    (match[4].include?(':') ? match[4] : match[4][0, 3] + ':' + match[4][3, 2])
  begin
    Time.iso8601("#{match[2]}T#{match[3]}#{normalized_zone}")
  rescue StandardError
    return nil
  end
  body = parserstudio_generic_profile_tokens(text, match.end(0))
  return nil unless body && body['tokens'].length.between?(8, 64)
  anchors = body['tokens'].first(5)
  return nil unless anchors.length == 5 &&
    anchors.all? { |value| value.match?(/\A[A-Za-z0-9_.:\/-]{1,128}\z/) } &&
    body['tokens'][1].match?(/\A[A-Z][A-Z0-9_]{1,15}\z/)
  port_like = lambda { |value| value.is_a?(String) && value.match?(/\A\d{1,5}\z/) }
  if body['tokens'].length >= 16 && port_like.call(body['tokens'][5]) && port_like.call(body['tokens'][7])
    return nil unless parserstudio_generic_ip_token(body['tokens'][4]) &&
      parserstudio_generic_ip_token(body['tokens'][6])
  end
  {
    'syslog'=>{'pri'=>match[1],'date'=>match[2],'time'=>match[3],'timezone'=>match[4]},
    'generic'=>{'mode'=>'iso_pri_positional','source_raw'=>text, **body}
  }
rescue StandardError
  nil
end

def parserstudio_generic_watchguard(text)
  match = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))?(?: +\(([0-9T:+-]{19,35})\))? +(firewall(?:\[\d{1,8}\])?): +/.match(text)
  return nil unless match
  return nil unless parserstudio_generic_valid_bsd_clock(match[2], match[3], match[4])
  return nil if match[1] && !Integer(match[1], 10).between?(0, 191)
  if match[7]
    begin
      Time.iso8601(match[7])
    rescue StandardError
      return nil
    end
  end
  body = parserstudio_generic_profile_tokens(text, match.end(0))
  return nil unless body && !body['tokens'].empty? &&
    ['Allow','Deny','Drop'].include?(body['tokens'][0])
  msg_id = body['kv']['msg_id']
  return nil unless msg_id.is_a?(String) && msg_id.match?(/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/)
  return nil if body['tokens'].count { |value| parserstudio_generic_ip_token(value) } < 2
  header = {'month'=>match[2], 'day'=>match[3], 'time'=>match[4],
            'hostname'=>match[5], 'app_tag'=>match[8]}
  header['pri'] = match[1] if match[1]
  header['serial'] = match[6] if match[6]
  header['device_time'] = match[7] if match[7]
  {'watchguard_header'=>header, 'watchguard'=>body}
end

def parserstudio_generic_watchguard_message(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))? +\(([0-9T:+-]{19,35})\) +(firewall(?:\[\d{1,8}\])?): +msg_id="([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})" +(.+)\z/.match(text)
  return nil unless match
  return nil unless parserstudio_generic_valid_bsd_clock(match[2], match[3], match[4])
  return nil if match[1] && !Integer(match[1], 10).between?(0, 191)
  begin
    Time.iso8601(match[7])
  rescue StandardError
    return nil
  end
  header = {'month'=>match[2], 'day'=>match[3], 'time'=>match[4],
            'hostname'=>match[5], 'device_time'=>match[7], 'app_tag'=>match[8]}
  header['pri'] = match[1] if match[1]
  header['serial'] = match[6] if match[6]
  {
    'watchguard_header'=>header,
    'watchguard_message'=>{'source_raw'=>text, 'msg_id'=>match[9], 'message'=>match[10]}
  }
rescue StandardError
  nil
end

def parserstudio_generic_dual_timestamp_session(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +1 +(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) +(\S{1,255}) +([A-Za-z0-9_.-]{1,64}): +- +- +- +(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}) +- +(\S{1,255}) +- +\[([^\]\r\n]{1,255})\] +(.+?) +- +(.+)\z/.match(text)
  return nil unless match
  return nil unless parserstudio_generic_valid_bsd_clock(match[1], match[2], match[3])
  begin
    Time.iso8601(match[5])
    Time.iso8601("#{match[8]}T#{match[9]}Z")
  rescue StandardError
    return nil
  end
  {
    'syslog'=>{'month'=>match[1],'day'=>match[2],'time'=>match[3],
      'hostname'=>match[4],'version'=>'1','timestamp'=>match[5],
      'source'=>match[6],'app_tag'=>match[7]},
    'session_envelope'=>{'source_raw'=>text,'event_date'=>match[8],
      'event_time'=>match[9],'node'=>match[10],'client'=>match[11],
      'identity'=>match[12],'message'=>match[13]}
  }
rescue StandardError
  nil
end

def parserstudio_generic_bsd_bracket_pid_message(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  match = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +([A-Za-z0-9_.-]{1,128}): +\[(\d{1,8})\]: +(.+)\z/.match(text)
  return nil unless match && parserstudio_generic_valid_bsd_clock(match[2], match[3], match[4])
  return nil if match[1] && !Integer(match[1], 10).between?(0, 191)
  syslog={'month'=>match[2],'day'=>match[3],'time'=>match[4],
          'hostname'=>match[5],'app_tag'=>match[6]}
  syslog['pri']=match[1] if match[1]
  {'syslog'=>syslog,
   'generic'=>{'mode'=>'bsd_bracket_pid_message','source_raw'=>text,
               'pid'=>match[7],'message'=>match[8]}}
rescue StandardError
  nil
end

def parserstudio_generic_juniper_legacy(text)
  head = /\A([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +(\S+) +([^:\s]{1,128}): +/.match(text)
  return nil unless head && head[5] == 'RT_FLOW'
  return nil unless parserstudio_generic_valid_bsd_clock(head[1], head[2], head[3])
  event = /\A(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.match(text[head.end(0)..-1].to_s)
  return nil unless event
  body = parserstudio_generic_profile_tokens(text, head.end(0) + event[0].length)
  return nil unless body && body['tokens'].any? {
    |value| value.match?(/\A[^\/\s]+\/[0-9]{1,5}->[^\/\s]+\/[0-9]{1,5}\z/)
  }
  {
    'syslog'=>{'month'=>head[1], 'day'=>head[2], 'time'=>head[3],
               'hostname'=>head[4], 'app_tag'=>head[5]},
    'juniper'=>{'event'=>event[1], **body}
  }
end

def parserstudio_generic_delimited_comma_kv(text)
  return nil if text.bytesize > 8192
  parts = parserstudio_split_escaped(text, ',')
  return nil unless parts && parts.length >= 4
  fields = {}
  prefix = ''
  parsed = 0
  safe = /\A[A-Za-z0-9][A-Za-z0-9 ._:\/()#-]{0,127}\z/
  parts.each_with_index do |raw_segment, index|
    segment = raw_segment.strip
    next if segment.empty?
    eq = segment.index('=')
    return nil unless eq && eq > 0
    before = segment[0...eq].rstrip
    key = before.strip
    if index == 0
      cut = [before.rindex(': '), before.rindex('. ')].compact.max
      if cut
        suffix = before[(cut + 2)..-1].to_s.strip
        if suffix.match?(safe)
          key = suffix
          prefix = before[0...(cut + 2)].strip
        end
      end
    end
    return nil unless key.match?(safe) && parserstudio_generic_source_key_safe(key)
    value = segment[(eq + 1)..-1].to_s.strip
    if value.length >= 2 && ((value.start_with?('"') && value.end_with?('"')) ||
       (value.start_with?("'") && value.end_with?("'")))
      value = value[1...-1]
    elsif value.start_with?('"', "'") || value.end_with?('"', "'")
      return nil
    end
    previous = fields[key]
    fields[key] = previous.nil? ? value : previous.is_a?(Array) ? previous + [value] : [previous, value]
    parsed += 1
  end
  return nil if parsed < 4
  prefix_tokens = prefix.empty? ? [] : prefix.split(/[ \t]+/).map { |value|
    value.length > 1 && [':', ','].include?(value[-1]) ? value[0...-1] : value
  }
  return nil if prefix_tokens.length > 64 || prefix_tokens.any? { |value| value.empty? || value.bytesize > 256 }
  {'generic'=>{'mode'=>'delimited_kv', 'delimiter'=>',',
               'prefix_tokens'=>prefix_tokens, 'fields'=>fields}}
end

def parserstudio_generic_rfc3164_delimited_comma_kv(text)
  return nil if text.bytesize > 8192
  head = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +([A-Za-z0-9_.-]{1,128}): +/.match(text)
  return nil unless head && parserstudio_generic_valid_bsd_clock(head[2], head[3], head[4])
  return nil if head[1] && !Integer(head[1], 10).between?(0, 191)
  body = parserstudio_generic_delimited_comma_kv(text[head.end(0)..-1].to_s)
  return nil unless body
  syslog = {'month'=>head[2], 'day'=>head[3], 'time'=>head[4],
            'host'=>head[5], 'tag'=>head[6]}
  syslog['pri'] = head[1] if head[1]
  {'syslog'=>syslog, 'generic'=>body['generic']}
end

def parserstudio_generic_panos_traffic_fields(values)
  return nil unless values.length >= 53 && values[3].to_s == 'TRAFFIC'
  values = values.map { |value| value.to_s }
  datetime = /\A\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\z/
  ip = /\A(?:\d{1,3}\.){3}\d{1,3}\z/
  valid_ip = lambda { |value|
    value.match?(ip) && value.split('.').all? { |part| Integer(part, 10).between?(0, 255) }
  rescue ArgumentError
    false
  }
  return nil unless [1,6,21,35].all? { |index| values[index].to_s.match?(datetime) }
  return nil unless [7,8,9,10].all? { |index| valid_ip.call(values[index].to_s) }
  return nil unless [24,25,26,27].all? { |index|
    value=values[index].to_s
    value.match?(/\A\d{1,5}\z/) && Integer(value,10).between?(0,65_535)
  }
  return nil unless values[29].to_s.match?(/\A[A-Za-z0-9_.-]{1,24}\z/) &&
    values[30].to_s.match?(/\A[A-Za-z0-9_. -]{1,64}\z/)
  names=[
    'domain','receive_time','serial','type','subtype','config_version','time_generated',
    'src','dst','natsrc','natdst','rule','srcuser','dstuser','app','vsys','from','to',
    'inbound_if','outbound_if','logset','time_received','sessionid','repeatcnt','sport',
    'dport','natsport','natdport','flags','protocol','action','bytes','bytes_sent',
    'bytes_received','packets','start_time','elapsed','category','seqno','actionflags',
    'srcloc','dstloc','cpadding','pkts_sent','pkts_received','session_end_reason',
    'dg_hier_level_1','dg_hier_level_2','dg_hier_level_3','dg_hier_level_4',
    'vsys_name','device_name','action_source'
  ]
  names=names[0...38]+['padding']+names[38..-1] if values.length >= 54
  fields={}
  values.each_with_index { |value,index| fields[names[index] || "field_#{index}"] = value }
  fields
end

def parserstudio_generic_rfc3164_positional_csv(text)
  return nil if text.bytesize > 8192
  head = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +/.match(text)
  return nil unless head && parserstudio_generic_valid_bsd_clock(head[2], head[3], head[4])
  return nil if head[1] && !Integer(head[1], 10).between?(0, 191)
  body = text[head.end(0)..-1].to_s
  return nil if body.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*=/)
  begin
    values = CSV.parse_line(body, col_sep: ',', liberal_parsing: false, strip: false)
  rescue CSV::MalformedCSVError
    return nil
  end
  return nil unless values && values.length.between?(12, 100) && values[0].to_s.match?(/\A[0-9]{1,10}\z/)
  ip = /\A(?:\d{1,3}\.){3}\d{1,3}\z/
  ips = values.count do |value|
    candidate=value.to_s
    candidate.match?(ip) && candidate.split('.').all? { |part| Integer(part, 10).between?(0, 255) }
  rescue ArgumentError
    false
  end
  category = /\A(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION)\z/
  return nil unless ips >= 2 && values.any? { |value| value.to_s.match?(category) }
  values=values.map { |value| value.to_s }
  panos=parserstudio_generic_panos_traffic_fields(values)
  columns={}
  values.each_with_index { |value,index| columns["column_#{index}"] = value }
  syslog={'month'=>head[2],'day'=>head[3],'time'=>head[4],'hostname'=>head[5]}
  syslog['pri']=head[1] if head[1]
  {'syslog'=>syslog,
   'generic'=>panos ?
     {'mode'=>'panos_traffic_csv','delimiter'=>',','source_raw'=>text,'fields'=>panos} :
     {'mode'=>'rfc3164_positional_csv','delimiter'=>',','source_raw'=>text,'columns'=>columns}}
end


def parserstudio_generic_envelope_pri(pri_text)
  return {} if pri_text.nil?
  priority=Integer(pri_text,10)
  return nil unless priority.between?(0,191)
  {'pri'=>pri_text,'facility'=>priority/8,'severity'=>priority%8}
rescue StandardError
  nil
end

def parserstudio_generic_envelope_calendar(year,month,day,time,zone='+00:00')
  match=/\A(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\z/.match(time)
  return false unless match
  Time.new(Integer(year,10),Integer(month,10),Integer(day,10),
           Integer(match[1],10),Integer(match[2],10),Integer(match[3],10),zone)
  true
rescue StandardError
  false
end

def parserstudio_generic_envelope_decorate(syslog,message)
  tag=/\A([A-Za-z0-9_.@\/-]{1,128})(?:\[(\d{1,10})\])?:[ \t]*(.*)\z/m.match(message)
  if tag && !['CEF','LEEF'].include?(tag[1])
    syslog=syslog.merge('appname'=>tag[1])
    syslog['procid']=tag[2] if tag[2]
    message=tag[3].to_s
  end
  [syslog,message]
end

def parserstudio_generic_syslog_envelope(text)
  return nil if text.empty? || text.bytesize>8192 || text.include?("\x00") ||
    text.include?("\r") || text.include?("\n")
  pri=nil
  rest=text
  if text.start_with?('<')
    head=/\A<(\d{1,3})>/.match(text)
    return nil unless head
    pri=head[1]
    return nil unless parserstudio_generic_envelope_pri(pri)
    rest=text[head.end(0)..-1].to_s
  end
  rest=rest.lstrip
  return nil if rest.empty?
  pri_fields=parserstudio_generic_envelope_pri(pri)
  return nil unless pri_fields

  if pri
    rfc=/\A(1) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +(.*)\z/m.match(rest)
    if rfc
      timestamp=rfc[2]
      return nil unless timestamp=='-' ||
        (timestamp.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})\z/) &&
         begin Time.iso8601(timestamp); true rescue false end)
      [[rfc[3],255],[rfc[4],48],[rfc[5],128],[rfc[6],32]].each do |pair|
        token,maximum=pair
        return nil unless token.bytesize<=maximum && token.match?(/\A[!-~]+\z/)
      end
      begin
        structured,message=parserstudio_rfc5424_sd(rfc[7])
      rescue StandardError
        return nil
      end
      syslog={'variant'=>'rfc5424','confidence'=>'strict',**pri_fields,'version'=>'1'}
      syslog['timestamp']=timestamp unless timestamp=='-'
      syslog['hostname']=rfc[3] unless rfc[3]=='-'
      syslog['appname']=rfc[4] unless rfc[4]=='-'
      syslog['procid']=rfc[5] unless rfc[5]=='-'
      syslog['msgid']=rfc[6] unless rfc[6]=='-'
      syslog['structuredData']=structured
      return [syslog,message.to_s]
    end
  end

  month_days={'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,
              'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}
  before=/\A([A-Z][a-z]{2}) +(\d{1,2}) +(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if before && parserstudio_generic_valid_bsd_clock(before[1],before[2],before[4]) &&
     Integer(before[3],10).between?(1900,9999)
    syslog={'variant'=>'rfc3164_year_before_time','confidence'=>'strong',**pri_fields,
            'month'=>before[1],'day'=>before[2],'year'=>before[3],
            'time'=>before[4],'hostname'=>before[5]}
    return parserstudio_generic_envelope_decorate(syslog,before[6].to_s)
  end
  after=/\A([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4}) +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if after && parserstudio_generic_valid_bsd_clock(after[1],after[2],after[3]) &&
     Integer(after[4],10).between?(1900,9999)
    syslog={'variant'=>'rfc3164_year_after_time','confidence'=>'strong',**pri_fields,
            'month'=>after[1],'day'=>after[2],'time'=>after[3],
            'year'=>after[4],'hostname'=>after[5]}
    return parserstudio_generic_envelope_decorate(syslog,after[6].to_s)
  end
  classic=/\A([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if classic && parserstudio_generic_valid_bsd_clock(classic[1],classic[2],classic[3])
    syslog={'variant'=>'rfc3164','confidence'=>'strict',**pri_fields,
            'month'=>classic[1],'day'=>classic[2],'time'=>classic[3],
            'hostname'=>classic[4]}
    return parserstudio_generic_envelope_decorate(syslog,classic[5].to_s)
  end

  rfc3339=/\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if rfc3339
    begin
      Time.iso8601(rfc3339[1])
      syslog={'variant'=>'rfc3339_loose','confidence'=>'strong',**pri_fields,
              'timestamp'=>rfc3339[1],'hostname'=>rfc3339[2]}
      return parserstudio_generic_envelope_decorate(syslog,rfc3339[3].to_s)
    rescue StandardError
      return nil
    end
  end

  iso=/\A(\d{4})-(\d{2})-(\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(?: +(Z|[+-]\d{2}:?\d{2}))? +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if iso && parserstudio_generic_envelope_calendar(iso[1],iso[2],iso[3],iso[4],iso[5]||'+00:00')
    syslog={'variant'=>'iso_space','confidence'=>'strong',**pri_fields,
            'year'=>iso[1],'timestamp'=>"#{iso[1]}-#{iso[2]}-#{iso[3]} #{iso[4]}",
            'time'=>iso[4],'hostname'=>iso[6]}
    syslog['timezone']=iso[5] if iso[5]
    return parserstudio_generic_envelope_decorate(syslog,iso[7].to_s)
  end

  slash=/\A(\d{4})\/(\d{2})\/(\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(?: +(Z|[+-]\d{2}:?\d{2}))? +(\S{1,255})(?: +(.*))?\z/m.match(rest)
  if slash && parserstudio_generic_envelope_calendar(slash[1],slash[2],slash[3],slash[4],slash[5]||'+00:00')
    syslog={'variant'=>'slash_date','confidence'=>'strong',**pri_fields,
            'year'=>slash[1],'timestamp'=>"#{slash[1]}/#{slash[2]}/#{slash[3]} #{slash[4]}",
            'time'=>slash[4],'hostname'=>slash[6]}
    syslog['timezone']=slash[5] if slash[5]
    return parserstudio_generic_envelope_decorate(syslog,slash[7].to_s)
  end

  return [{'variant'=>'pri_only','confidence'=>'partial',**pri_fields},rest] if pri
  nil
rescue StandardError
  nil
end

def parserstudio_generic_envelope_json_safe(value,depth=0,state=nil)
  state ||= {'nodes'=>0}
  state['nodes'] += 1
  return false if depth>8 || state['nodes']>2048
  if value.is_a?(Hash)
    value.each do |key,item|
      return false unless key.is_a?(String) && key.bytesize<=256 &&
        parserstudio_generic_source_key_safe(key) &&
        parserstudio_generic_envelope_json_safe(item,depth+1,state)
    end
  elsif value.is_a?(Array)
    return false if value.length>1024
    return false unless value.all? { |item| parserstudio_generic_envelope_json_safe(item,depth+1,state) }
  end
  true
end

def parserstudio_generic_envelope_bracket_kv(text)
  return nil unless text.start_with?('[') && text.end_with?(']') && text.bytesize<=8192
  parts=parserstudio_split_escaped(text[1...-1],';')
  return nil unless parts
  fields={}
  parts.each do |raw_segment|
    segment=raw_segment.strip
    next if segment.empty?
    delimiter=/:\s*"/.match(segment)
    return nil unless delimiter && delimiter.begin(0)>0
    key=segment[0...delimiter.begin(0)].strip
    return nil unless key.match?(/\A[A-Za-z_][A-Za-z0-9_.#:-]{0,127}\z/) &&
      parserstudio_generic_source_key_safe(key)
    encoded=segment[(delimiter.begin(0)+1)..-1].to_s.strip
    return nil unless encoded.length>=2 && encoded.start_with?('"') && encoded.end_with?('"')
    value=encoded[1...-1]
    previous=fields[key]
    fields[key]=previous.nil? ? value : previous.is_a?(Array) ? previous+[value] : [previous,value]
    return nil if fields.length>100
  end
  fields.length>=2 ? fields : nil
end

def parserstudio_generic_envelope_juniper(text)
  event=/\A(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.match(text)
  return nil unless event
  body=parserstudio_generic_profile_tokens(text,event[0].length)
  return nil unless body && body['tokens'].any? {
    |value| value.match?(/\A[^\/\s]+\/[0-9]{1,5}->[^\/\s]+\/[0-9]{1,5}\z/)
  }
  {'event'=>event[1],**body}
end

def parserstudio_generic_envelope_watchguard(text)
  head=/\A(?:([A-Za-z0-9.-]{2,64}) +)?(?:\(([0-9T:+-]{19,35})\) +)?(firewall(?:\[\d{1,8}\])?): +/.match(text)
  return nil unless head
  begin
    Time.iso8601(head[2]) if head[2]
  rescue StandardError
    return nil
  end
  body=parserstudio_generic_profile_tokens(text,head[0].length)
  return nil unless body && !body['tokens'].empty? &&
    ['Allow','Deny','Drop'].include?(body['tokens'][0])
  msg_id=body['kv']['msg_id']
  return nil unless msg_id.is_a?(String) && msg_id.match?(/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/)
  ip=/\A(?:\d{1,3}\.){3}\d{1,3}\z/
  ips=body['tokens'].count { |value| value.match?(ip) &&
    value.split('.').all? { |part| Integer(part,10).between?(0,255) rescue false } }
  return nil if ips<2
  header={'app_tag'=>head[3]}
  header['serial']=head[1] if head[1]
  header['device_time']=head[2] if head[2]
  [header,body]
end

def parserstudio_generic_envelope_csv(text)
  CSV.parse_line(text,col_sep:',',liberal_parsing:false,strip:false)
rescue CSV::MalformedCSVError
  nil
end

def parserstudio_generic_envelope_panos(values)
  return nil unless values && values.length.between?(7,150)
  values=values.map { |value| value.to_s }
  return nil unless values[0].match?(/\A\d{0,10}\z/)
  received=/\A(\d{4})\/(\d{2})\/(\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)\z/.match(values[1])
  return nil unless received &&
    parserstudio_generic_envelope_calendar(received[1],received[2],received[3],received[4])
  return nil unless values[2].match?(/\A[A-Za-z0-9_.:-]{4,64}\z/)
  return nil unless values[3].match?(/\A(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE)\z/)
  columns={}
  values.each_with_index { |value,index| columns["column_#{index}"]=value }
  [values,columns]
end

def parserstudio_generic_envelope_security_csv(values)
  return nil unless values && values.length.between?(12,150)
  values=values.map { |value| value.to_s }
  ip=/\A(?:\d{1,3}\.){3}\d{1,3}\z/
  valid=lambda { |value| value.match?(ip) &&
    value.split('.').all? { |part| Integer(part,10).between?(0,255) rescue false } }
  return nil if values.count { |value| valid.call(value) }<2
  columns={}
  values.each_with_index { |value,index| columns["column_#{index}"]=value }
  columns
end

def parserstudio_generic_syslog_envelope_structured(text)
  parsed=parserstudio_generic_syslog_envelope(text)
  return nil unless parsed
  syslog,message=parsed
  return nil if message.nil?

  if message.match?(/\A%(?:ASA|FTD)-/)
    asa=parserstudio_generic_asa(message)
    return nil unless asa && asa['asa'].is_a?(Hash)
    vendor_syslog=asa['syslog'].is_a?(Hash) ? asa['syslog'] : {}
    fields=asa['asa'].dup
    fields['source_raw']=text
    fields['message_raw']=message
    return {'syslog'=>syslog.merge(vendor_syslog),'asa'=>fields}
  end

  if syslog['appname']=='RT_FLOW'
    juniper=parserstudio_generic_envelope_juniper(message)
    return nil unless juniper
    juniper=juniper.merge('source_raw'=>text,'message_raw'=>message)
    return {'syslog'=>syslog,'juniper'=>juniper}
  end

  if message.start_with?('[')
    bracket=parserstudio_generic_envelope_bracket_kv(message)
    return nil unless bracket
    return {'syslog'=>syslog,'body'=>bracket,
      'generic'=>{'mode'=>'syslog_envelope_bracket_colon_kv',
                  'source_raw'=>text,'message_raw'=>message}}
  end

  watchguard=parserstudio_generic_envelope_watchguard(message)
  if watchguard
    header,body=watchguard
    body=body.merge('source_raw'=>text,'message_raw'=>message)
    return {'syslog'=>syslog,'watchguard_header'=>header,'watchguard'=>body}
  end
  return nil if message.match?(/\bfirewall(?:\[\d{1,8}\])?: +msg_id=/)

  if message.start_with?('CEF:')
    return nil unless message.start_with?('CEF:0|')
    begin
      body=parserstudio_cef(message)
    rescue StandardError
      return nil
    end
    return {'syslog'=>syslog,'body'=>body,
      'generic'=>{'mode'=>'syslog_envelope_cef','source_raw'=>text,'message_raw'=>message}}
  end

  if message.start_with?('LEEF:')
    return nil unless message.match?(/\ALEEF:(?:1\.0|2\.0)\|/)
    begin
      body=parserstudio_leef(message)
    rescue StandardError
      return nil
    end
    return {'syslog'=>syslog,'body'=>body,
      'generic'=>{'mode'=>'syslog_envelope_leef','source_raw'=>text,'message_raw'=>message}}
  end

  if message.start_with?('{')
    begin
      body=parserstudio_json_object(message)
    rescue StandardError
      return nil
    end
    return nil unless parserstudio_generic_envelope_json_safe(body)
    return {'syslog'=>syslog,'body'=>body,
      'generic'=>{'mode'=>'syslog_envelope_json','source_raw'=>text,'message_raw'=>message}}
  end

  values=parserstudio_generic_envelope_csv(message)
  panos_like=values && values.length>=7 &&
    values[0].to_s.match?(/\A\d{0,10}\z/) &&
    values[1].to_s.match?(/\A\d{4}\/\d{2}\/\d{2} +\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\z/) &&
    values[2].to_s.match?(/\A[A-Za-z0-9_.:-]{4,64}\z/) &&
    values[3].to_s.match?(/\A[A-Z][A-Z0-9_]{2,31}\z/)
  panos=parserstudio_generic_envelope_panos(values)
  if panos
    panos_values,columns=panos
    named=parserstudio_generic_panos_traffic_fields(panos_values)
    generic=named ?
      {'mode'=>'panos_traffic_csv','profile'=>'panos','delimiter'=>',',
       'source_raw'=>text,'message_raw'=>message,'fields'=>named} :
      {'mode'=>'syslog_envelope_positional_csv','profile'=>'panos','delimiter'=>',',
       'source_raw'=>text,'message_raw'=>message,'columns'=>columns}
    return {'syslog'=>syslog,'generic'=>generic}
  end
  return nil if panos_like

  positional=parserstudio_generic_envelope_security_csv(values)
  if positional
    return {'syslog'=>syslog,
      'generic'=>{'mode'=>'syslog_envelope_positional_csv','delimiter'=>',',
                  'source_raw'=>text,'message_raw'=>message,'columns'=>positional}}
  end

  comma=parserstudio_generic_delimited_comma_kv(message)
  if comma && comma['generic'].is_a?(Hash)
    generic=comma['generic'].merge('source_raw'=>text,'message_raw'=>message)
    return {'syslog'=>syslog,'generic'=>generic}
  end

  spaced=parserstudio_generic_space_kv(message)
  if spaced && spaced['generic'].is_a?(Hash)
    generic=spaced['generic'].merge('source_raw'=>text,'message_raw'=>message)
    return {'syslog'=>syslog,'generic'=>generic}
  end

  nil
end

def parserstudio_generic_asa(text)
  return nil if text.bytesize > 8192 || text.include?("\x00")
  id_pattern = /%(ASA|FTD)-(\d)-(\d{6}):[ \t]*/
  id = id_pattern.match(text)
  return nil unless id
  return nil if id_pattern.match(text, id.end(0))
  severity = Integer(id[2], 10)
  return nil unless severity.between?(0, 7)
  body = text[id.end(0)..-1].to_s
  built = /\A(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)\z/.match(body)
  deny = /\A(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})\z/.match(body)
  deny_access = /\A(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?:(?<src_context>v[12]):)?(?<src_interface>[A-Za-z0-9_.-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<src_port>[0-9]{1,5}))? dst (?:(?<dst_context>v[12]):)?(?<dst_interface>[A-Za-z0-9_.-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<dst_port>[0-9]{1,5}))? by access-group \"(?<access_group>[^\"\r\n]{0,128})\" \[(?<flag_1>0x[0-9A-Fa-f]+), (?<flag_2>0x[0-9A-Fa-f]+)\]\z/.match(body)
  full = built || deny || deny_access
  return nil unless full
  fields = {'source_raw' => text, 'product' => id[1], 'severity' => id[2], 'message_id' => id[3]}
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
    header = /\A(?:<(\d{1,3})>)?([A-Z][a-z]{2})[ ]+(\d{1,2})[ ]+(?:(\d{4})[ ]+)?(\d{2}):(\d{2}):(\d{2})[ ]+([^\s:]{1,255})(?:[ ]+([A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?))?[ ]*:?[ ]*\z/.match(prefix)
    if header
      month_days = {'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,
        'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}
      priority = header[1] ? Integer(header[1], 10) : nil
      day = Integer(header[3], 10)
      year = header[4] ? Integer(header[4], 10) : nil
      hour = Integer(header[5], 10)
      minute = Integer(header[6], 10)
      second = Integer(header[7], 10)
      return nil unless (!priority || priority.between?(0,191)) &&
        month_days[header[2]] && day.between?(1, month_days[header[2]]) &&
        (!year || year.between?(1,9999)) &&
        hour.between?(0, 23) && minute.between?(0, 59) && second.between?(0, 59)
      syslog['pri'] = header[1] if header[1]
      syslog['month'] = header[2]
      syslog['day'] = header[3]
      syslog['year'] = header[4] if header[4]
      syslog['time'] = "#{header[5]}:#{header[6]}:#{header[7]}"
      syslog['hostname'] = header[8]
      syslog['source_tag'] = header[9] if header[9]
    else
      facility = /\A([A-Z0-9]{2,16})\.([A-Z]{2,16}): +([!-~]{1,255}) +\z/.match(prefix)
      host_only = /\A([!-~]{1,255}) +: +\z/.match(prefix)
      if facility
        syslog['source_facility'] = facility[1]
        syslog['source_level'] = facility[2]
        syslog['hostname'] = facility[3]
      elsif host_only
        syslog['hostname'] = host_only[1]
      else
        return nil
      end
    end
  end
  {'syslog' => syslog, 'asa' => fields}
end
