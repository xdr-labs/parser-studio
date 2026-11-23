# GENERATED FILE - DO NOT EDIT.
# Parser Studio grammar: the Generic Structural routes (emitted for generic_structural projects only).
# Source: src/grammar/readEvent.ts (readEvent), src/grammar/extractEvent.ts (extractEvent), src/grammar/extractEvent.ts (tokenizeCsvRow) and the functions they reach.
# Regenerate with: node scripts/grammar/ts2rb/generate.mjs --write
# CI runs the generator with --verify, so a hand edit of this file fails the gate.

# src/genericStructural.ts: GENERIC_FAMILY_MODES
def psg_k_generic_family_modes
  @psg_k_generic_family_modes ||= ['structured_family_cef', 'structured_family_leef', 'syslog_envelope_cef', 'syslog_envelope_leef', 'syslog_envelope_leef2_implicit_tab', 'leef2_implicit_tab']
end

# src/grammar/genericParseStatus.ts: GRAMMAR_OWNED_NODES
def psg_k_grammar_owned_nodes
  @psg_k_grammar_owned_nodes ||= ['generic', 'watchguard_message', 'session_envelope', 'asa', 'juniper', 'watchguard']
end

# src/genericStructural.ts: MERAKI_RECORD_MODES
def psg_k_meraki_record_modes
  @psg_k_meraki_record_modes ||= {'flows' => 'meraki_flows', 'firewall' => 'meraki_firewall', 'vpn_firewall' => 'meraki_vpn_firewall', 'cellular_firewall' => 'meraki_cellular_firewall', 'bridge_anyconnect_client_vpn_firewall' => 'meraki_anyconnect_firewall', 'urls' => 'meraki_urls', 'ids-alerts' => 'meraki_ids_alerts', 'security_event' => 'meraki_security_event'}
end

# src/syslogEnvelope.ts: MONTH_DAYS
def psg_k_month_days
  @psg_k_month_days ||= {'Jan' => 31, 'Feb' => 29, 'Mar' => 31, 'Apr' => 30, 'May' => 31, 'Jun' => 30, 'Jul' => 31, 'Aug' => 31, 'Sep' => 30, 'Oct' => 31, 'Nov' => 30, 'Dec' => 31}
end

# src/genericStructural.ts: PANOS_SYSTEM
def psg_k_panos_system
  @psg_k_panos_system ||= ['domain', 'receive_time', 'serial', 'type', 'subtype', 'config_version', 'time_generated', 'vsys', 'eventid', 'object', 'column_10', 'column_11', 'module', 'severity', 'opaque', 'seqno', 'actionflags', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_name', 'column_23', 'column_24', 'high_res_timestamp']
end

# src/genericStructural.ts: PANOS_THREAT
def psg_k_panos_threat
  @psg_k_panos_threat ||= ['domain', 'receive_time', 'serial', 'type', 'subtype', 'config_version', 'time_generated', 'src', 'dst', 'natsrc', 'natdst', 'rule', 'srcuser', 'dstuser', 'app', 'vsys', 'from', 'to', 'inbound_if', 'outbound_if', 'logset', 'time_received', 'sessionid', 'repeatcnt', 'sport', 'dport', 'natsport', 'natdport', 'flags', 'protocol', 'action', 'misc', 'threatid', 'category', 'severity', 'direction', 'seqno', 'actionflags', 'srcloc', 'dstloc', 'column_40', 'contenttype', 'pcap_id', 'filedigest', 'cloud', 'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 'subject', 'recipient', 'reportid', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_name']
end

# src/genericStructural.ts: PANOS_TRAFFIC_53
def psg_k_panos_traffic_53
  @psg_k_panos_traffic_53 ||= ['domain', 'receive_time', 'serial', 'type', 'subtype', 'config_version', 'time_generated', 'src', 'dst', 'natsrc', 'natdst', 'rule', 'srcuser', 'dstuser', 'app', 'vsys', 'from', 'to', 'inbound_if', 'outbound_if', 'logset', 'time_received', 'sessionid', 'repeatcnt', 'sport', 'dport', 'natsport', 'natdport', 'flags', 'protocol', 'action', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'start_time', 'elapsed', 'category', 'seqno', 'actionflags', 'srcloc', 'dstloc', 'cpadding', 'pkts_sent', 'pkts_received', 'session_end_reason', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_name', 'action_source']
end

# src/genericStructural.ts: PANOS_TRAFFIC_54
def psg_k_panos_traffic_54
  @psg_k_panos_traffic_54 ||= ['domain', 'receive_time', 'serial', 'type', 'subtype', 'config_version', 'time_generated', 'src', 'dst', 'natsrc', 'natdst', 'rule', 'srcuser', 'dstuser', 'app', 'vsys', 'from', 'to', 'inbound_if', 'outbound_if', 'logset', 'time_received', 'sessionid', 'repeatcnt', 'sport', 'dport', 'natsport', 'natdport', 'flags', 'protocol', 'action', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'start_time', 'elapsed', 'category', 'padding', 'seqno', 'actionflags', 'srcloc', 'dstloc', 'cpadding', 'pkts_sent', 'pkts_received', 'session_end_reason', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_name', 'action_source']
end

# src/grammar/genericParseStatus.ts: PROVENANCE_COPIES
def psg_k_provenance_copies
  @psg_k_provenance_copies ||= ['source_raw', 'message_raw']
end

# src/genericStructural.ts: UNSAFE_SOURCE_KEYS
def psg_k_unsafe_source_keys
  @psg_k_unsafe_source_keys ||= {'__proto__' => true, 'constructor' => true, 'prototype' => true}
end

# src/grammar/genericParseStatus.ts: accounted
def psg_accounted(pair, leaves)
  written = nil
  written = psg_without_backslashes(pair['rawValue'])
  return psg_some(leaves, lambda { |(key, value)| (((key == pair['key']) && (((((value == pair['value']) || (value == pair['rawValue'])) || (psg_without_backslashes(value) == written)) || value.start_with?((pair['value'] + ' '))) || psg_without_backslashes(value).start_with?((written + ' ')))) || (value.include?((pair['key'] + '=')) && value.include?(pair['rawValue']))) })
end

# src/genericStructural.ts: asa
def psg_asa(raw)
  id = after = severity = built = deny = denyAccess = full = fields = value = port = syslog = prefix = header = monthDays = pri = day = year = hour = minute = second = facility = hostOnly = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  id = (/%(ASA|FTD)-([0-9])-([0-9]{6}):[ \t]*/.match(raw) || :psg_null)
  if (!psg_t(id) || psg_match_index(id).nil?)
    return :psg_null
  end
  after = psg_slice(raw, (psg_match_index(id) + psg_len(id[0])))
  if /%(?:ASA|FTD)-[0-9]-[0-9]{6}:[ \t]*/.match?(after)
    return :psg_null
  end
  severity = psg_num(id[2])
  if ((!psg_integer?(severity) || (severity < 0)) || (severity > 7))
    return :psg_null
  end
  built = (/\A(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.:\-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.:\-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)\z/.match(after) || :psg_null)
  deny = (/\A(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.:\-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.:\-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})\z/.match(after) || :psg_null)
  denyAccess = (/\A(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?:(?<src_context>v[12]):)?(?<src_interface>[A-Za-z0-9_.\-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<src_port>[0-9]{1,5}))? dst (?:(?<dst_context>v[12]):)?(?<dst_interface>[A-Za-z0-9_.\-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<dst_port>[0-9]{1,5}))? by access-group "(?<access_group>[^"\r\n]{0,128})" \[(?<flag_1>0x[0-9A-Fa-f]+), (?<flag_2>0x[0-9A-Fa-f]+)\]\z/.match(after) || :psg_null)
  full = (psg_null?(psg_t1 = (psg_null?(psg_t2 = built) ? deny : psg_t2)) ? denyAccess : psg_t1)
  if !psg_t(full)
    return :psg_null
  end
  fields = {'source_raw' => raw, 'product' => id[1], 'severity' => id[2], 'message_id' => id[3]}.merge!(psg_named_groups(full))
  ['src_port', 'dst_port', 'mapped_src_port', 'mapped_dst_port'].each do |name|
    value = fields[name]
    if value.nil?
      next
    end
    port = psg_num(value)
    if ((!psg_integer?(port) || (port < 0)) || (port > 65535))
      return :psg_null
    end
  end
  syslog = {'app_tag' => ('%' + id[1] + '-' + id[2] + '-' + id[3])}
  prefix = psg_slice(raw, 0, psg_match_index(id))
  if psg_t(prefix)
    header = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +(?:([0-9]{4}) +)?([0-9]{2}):([0-9]{2}):([0-9]{2}) +([^ \t\n\r\f\x0b:]{1,255})(?: +([A-Za-z_][A-Za-z0-9_.\-]{0,95}(?:\[[0-9]{1,8}\])?))? *:? *\z/.match(prefix) || :psg_null)
    if psg_t(header)
      monthDays = {'Jan' => 31, 'Feb' => 29, 'Mar' => 31, 'Apr' => 30, 'May' => 31, 'Jun' => 30, 'Jul' => 31, 'Aug' => 31, 'Sep' => 30, 'Oct' => 31, 'Nov' => 30, 'Dec' => 31}
      pri = (header[1].nil? ? nil : psg_num(header[1]))
      day = psg_num(header[3])
      year = (header[4].nil? ? nil : psg_num(header[4]))
      hour = psg_num(header[5])
      minute = psg_num(header[6])
      second = psg_num(header[7])
      if (((((((((((!pri.nil? && ((pri < 0) || (pri > 191))) || !psg_t(monthDays[header[2]])) || (day < 1)) || (day > monthDays[header[2]])) || (!year.nil? && ((year < 1) || (year > 9999)))) || (hour < 0)) || (hour > 23)) || (minute < 0)) || (minute > 59)) || (second < 0)) || (second > 59))
        return :psg_null
      end
      psg_assign(syslog, {}.merge!((!pri.nil? ? {'pri' => psg_str(pri)} : {})).merge!({'month' => header[2], 'day' => header[3]}).merge!((!year.nil? ? {'year' => header[4]} : {})).merge!({'time' => ((((header[5] + ':') + header[6]) + ':') + header[7]), 'hostname' => header[8]}).merge!((psg_t(header[9]) ? {'source_tag' => header[9]} : {})))
    else
      facility = (/\A([A-Z0-9]{2,16})\.([A-Z]{2,16}): +([!-~]{1,255}) +\z/.match(prefix) || :psg_null)
      hostOnly = (/\A([!-~]{1,255}) +: +\z/.match(prefix) || :psg_null)
      if psg_t(facility)
        psg_assign(syslog, {'source_facility' => facility[1], 'source_level' => facility[2], 'hostname' => facility[3]})
      elsif psg_t(hostOnly)
        psg_assign(syslog, {'hostname' => hostOnly[1]})
      else
        return :psg_null
      end
    end
  end
  return {'syslog' => syslog, 'asa' => fields}
end

# src/grammar/genericParseStatus.ts: bodyUnaccounted
def psg_body_unaccounted(fields)
  kind = text = generic = cells = body = record = nil
  kind = psg_get_tag(fields, 'bodyKind')
  text = psg_get_tag(fields, 'bodyText')
  if (!kind.is_a?(String) || !text.is_a?(String))
    return :psg_null
  end
  if (kind == 'positional_csv')
    generic = fields['generic']
    cells = (psg_null?(psg_t1 = (psg_null?(psg_t2 = generic) ? nil : psg_t2['columns'])) ? (psg_null?(psg_t3 = generic) ? nil : psg_t3['fields']) : psg_t1)
    if ((cells.equal?(:psg_null) || !(psg_typeof(cells) == 'object')) || cells.is_a?(Array))
      return 'the CSV cells of the event body are not where the extractor reports them'
    end
    return psg_positional_csv_unaccounted(text, cells.values)
  end
  body = fields['body']
  if ((body.equal?(:psg_null) || !(psg_typeof(body) == 'object')) || body.is_a?(Array))
    return 'the fields of the event body are not where the extractor reports them'
  end
  record = body
  if (kind == 'json')
    return psg_json_text_unaccounted(text, record)
  end
  return ((kind == 'cef') ? psg_cef_event_unaccounted(text, record) : psg_leef_event_unaccounted(text, record))
end

# src/genericStructural.ts: boundedEnvelopeJson
def psg_bounded_envelope_json(text)
  parsed = nodes = safe = nil
  safe = lambda { |value, depth|
  if ((depth > 8) || ((nodes += 1) > 2048))
    return false
  end
  if value.is_a?(Array)
    return ((value.length <= 1024) && psg_every(value, lambda { |item| safe.call(item, (depth + 1)) }))
  end
  if (psg_t(value) && (psg_typeof(value) == 'object'))
    value.to_a.each do |(key, item_2)|
      if ((!psg_source_key_safe(key) || (key.bytesize > 256)) || !safe.call(item_2, (depth + 1)))
        return false
      end
    end
  end
  return true
}
  if ((!text.start_with?('{') || (text.bytesize > 8192)) || text.include?("\u{0}"))
    return :psg_null
  end
  parsed = psg_parse_json_body(text)
  if ((!psg_t(parsed) || parsed.is_a?(Array)) || !(psg_typeof(parsed) == 'object'))
    return :psg_null
  end
  nodes = 0
  return (safe.call(parsed, 0) ? parsed : :psg_null)
end

# src/genericStructural.ts: bracketColonKv
def psg_bracket_colon_kv(raw)
  match = pri = inner = segments = body = segment = delimiter = key = encoded = value = previous = nil
  match = (/\A<([0-9]{1,3})>(1) ([^ \t\n\r\f\x0b]+) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[(?m:.)*\])[ \t]*\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  pri = psg_num(match[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !(psg_valid_rfc3339(match[3]) || psg_valid_unzoned_timestamp(match[3])))
    return :psg_null
  end
  inner = psg_slice(match[8], 1, (-1))
  if (inner.bytesize > 8192)
    return :psg_null
  end
  segments = psg_split_escaped_2(inner, ';')
  if !psg_t(segments)
    return :psg_null
  end
  body = {}
  segments.each do |rawSegment|
    segment = psg_replace(rawSegment, /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if !psg_t(segment)
      next
    end
    delimiter = (/:[ \t\n\r\f\x0b]*"/.match(segment) || :psg_null)
    if (!psg_t(delimiter) || (psg_match_index(delimiter) <= 0))
      return :psg_null
    end
    key = psg_replace(psg_slice(segment, 0, psg_match_index(delimiter)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (!/\A[A-Za-z_][A-Za-z0-9_.\#:\-]{0,127}\z/.match?(key) || !psg_source_key_safe(key))
      return :psg_null
    end
    encoded = psg_replace(psg_slice(segment, (psg_match_index(delimiter) + 1)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (((psg_len(encoded) < 2) || !encoded.start_with?('"')) || !encoded.end_with?('"'))
      return :psg_null
    end
    value = psg_slice(encoded, 1, (-1))
    previous = body[key]
    body[key] = (previous.nil? ? value : (previous.is_a?(Array) ? [*previous, value] : [previous, value]))
    if (body.keys.length > 100)
      return :psg_null
    end
  end
  if (body.keys.length < 2)
    return :psg_null
  end
  return {'syslog' => {'pri' => match[1], 'version' => match[2], 'timestamp' => match[3], 'hostname' => match[4], 'appname' => match[5], 'procid' => match[6], 'msgid' => match[7]}, 'body' => body}
end

# src/genericStructural.ts: bracketColonKvBody
def psg_bracket_colon_kv_body(text)
  inner = segments = body = segment = delimiter = key = encoded = value = previous = nil
  if ((!text.start_with?('[') || !text.end_with?(']')) || (text.bytesize > 8192))
    return :psg_null
  end
  inner = psg_slice(text, 1, (-1))
  segments = psg_split_escaped_2(inner, ';')
  if !psg_t(segments)
    return :psg_null
  end
  body = {}
  segments.each do |rawSegment|
    segment = psg_replace(rawSegment, /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if !psg_t(segment)
      next
    end
    delimiter = (/:[ \t\n\r\f\x0b]*"/.match(segment) || :psg_null)
    if (!psg_t(delimiter) || (psg_match_index(delimiter) <= 0))
      return :psg_null
    end
    key = psg_replace(psg_slice(segment, 0, psg_match_index(delimiter)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (!/\A[A-Za-z_][A-Za-z0-9_.\#:\-]{0,127}\z/.match?(key) || !psg_source_key_safe(key))
      return :psg_null
    end
    encoded = psg_replace(psg_slice(segment, (psg_match_index(delimiter) + 1)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (((psg_len(encoded) < 2) || !encoded.start_with?('"')) || !encoded.end_with?('"'))
      return :psg_null
    end
    value = psg_slice(encoded, 1, (-1))
    previous = body[key]
    body[key] = (previous.nil? ? value : (previous.is_a?(Array) ? [*previous, value] : [previous, value]))
    if (body.keys.length > 100)
      return :psg_null
    end
  end
  return ((body.keys.length >= 2) ? body : :psg_null)
end

# src/genericStructural.ts: bsdBracketPidMessageProfile
def psg_bsd_bracket_pid_message_profile(raw)
  match = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255}) +([A-Za-z0-9_.\-]{1,128}): +\[([0-9]{1,8})\]: +((?m:.)+)\z/.match(raw) || :psg_null)
  if (!psg_t(match) || !psg_valid_bsd_clock(match[2], match[3], match[4]))
    return :psg_null
  end
  if (!match[1].nil? && ((psg_num(match[1]) < 0) || (psg_num(match[1]) > 191)))
    return :psg_null
  end
  return {'syslog' => {}.merge!((!match[1].nil? ? {'pri' => match[1]} : {})).merge!({'month' => match[2], 'day' => match[3], 'time' => match[4], 'hostname' => match[5], 'app_tag' => match[6]}), 'generic' => {'mode' => 'bsd_bracket_pid_message', 'source_raw' => raw, 'pid' => match[7], 'message' => match[8]}}
end

# src/genericStructural.ts: bsdClassicPidMessageProfile
def psg_bsd_classic_pid_message_profile(raw)
  match = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([A-Za-z0-9_.\-]{1,128})\[([0-9]{1,8})\]: +([A-Za-z0-9_.\-]{1,128}): +([^\n]+)\z/.match(raw) || :psg_null)
  if (!psg_t(match) || !psg_valid_bsd_clock(match[2], match[3], match[4]))
    return :psg_null
  end
  if (!match[1].nil? && ((psg_num(match[1]) < 0) || (psg_num(match[1]) > 191)))
    return :psg_null
  end
  return {'syslog' => {}.merge!((!match[1].nil? ? {'pri' => match[1]} : {})).merge!({'month' => match[2], 'day' => match[3], 'time' => match[4], 'hostname' => match[5], 'app_tag' => match[7]}), 'generic' => {'mode' => 'bsd_classic_pid_message', 'source_raw' => raw, 'pid' => match[6], 'message' => match[8]}}
end

# src/genericStructural.ts: bsdTaggedMessageProfile
def psg_bsd_tagged_message_profile(raw)
  match = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255}) +([A-Za-z0-9_.\-]{1,128}): +([^\n]+)\z/.match(raw) || :psg_null)
  if (!psg_t(match) || !psg_valid_bsd_clock(match[2], match[3], match[4]))
    return :psg_null
  end
  if (!match[1].nil? && ((psg_num(match[1]) < 0) || (psg_num(match[1]) > 191)))
    return :psg_null
  end
  if /\A\[[0-9]+\]:/.match?(match[7])
    return :psg_null
  end
  if ((match[6] == 'RT_FLOW') && /\ART_FLOW_SESSION_/.match?(match[7]))
    return :psg_null
  end
  return {'syslog' => {}.merge!((!match[1].nil? ? {'pri' => match[1]} : {})).merge!({'month' => match[2], 'day' => match[3], 'time' => match[4], 'hostname' => match[5], 'app_tag' => match[6]}), 'generic' => {'mode' => 'bsd_tagged_message', 'source_raw' => raw, 'message' => match[7]}}
end

# src/grammar/genericParseStatus.ts: classifyGenericStructural
def psg_classify_generic_structural(raw, outcome)
  generic = mode = reasons = claim = leaves = lostPairs = unaccounted = nil
  if outcome.key?('thrown')
    return {'status' => 'ERROR', 'lostPairs' => [], 'reasons' => [('extractor raised: ' + psg_str(outcome['thrown']))]}
  end
  if (outcome['errors'].length > 0)
    return {'status' => 'UNKNOWN', 'lostPairs' => [], 'reasons' => psg_slice(outcome['errors'], 0, 4)}
  end
  if (outcome['fields'].keys.length == 0)
    return {'status' => 'UNKNOWN', 'lostPairs' => [], 'reasons' => ['no field was extracted']}
  end
  generic = outcome['fields']['generic']
  mode = ((psg_null?(psg_t1 = generic) ? nil : psg_t1['mode']).is_a?(String) ? generic['mode'] : psg_join(psg_filter(outcome['fields'].keys, lambda { |key| (key != 'syslog') }), '+'))
  reasons = []
  claim = (psg_null?(psg_t2 = psg_structured_family_claim(raw)) ? psg_enveloped_family_claim(raw) : psg_t2)
  if (psg_t(claim) && !psg_k_generic_family_modes.include?(mode))
    reasons.push((((('the line claims to be ' + claim) + ' but was read as generic key=value (legacy compatibility route): its ') + claim) + ' header is not parsed'))
  end
  if psg_enveloped_json_declined(raw)
    reasons.push('the message claims to be a JSON object that the JSON body contract does not read, but was read as free text (legacy compatibility route): its members are not parsed')
  end
  leaves = []
  psg_collect_fields(outcome['fields'], leaves)
  lostPairs = psg_filter(psg_independent_key_value_pairs(raw), lambda { |pair| !psg_accounted(pair, leaves) })
  psg_slice(lostPairs, 0, 4).each do |pair_2|
    reasons.push((('raw pair ' + pair_2['key']) + '= is not present with its value in the extracted fields'))
  end
  unaccounted = psg_body_unaccounted(outcome['fields'])
  if !unaccounted.equal?(:psg_null)
    reasons.push(unaccounted)
  end
  return {'status' => ((reasons.length > 0) ? 'PARTIAL' : 'FULL'), 'lostPairs' => lostPairs, 'reasons' => reasons, 'mode' => mode}
end

# src/grammar/genericParseStatus.ts: collect
def psg_collect(value, key, out)
  if value.is_a?(Array)
    value.each do |child|
      psg_collect(child, key, out)
    end
    return nil
  end
  if (!value.equal?(:psg_null) && (psg_typeof(value) == 'object'))
    value.to_a.each do |(childKey, child_2)|
      psg_collect(child_2, childKey, out)
    end
    return nil
  end
  if (!value.nil? && !value.equal?(:psg_null))
    out.push([key, psg_str(value)])
  end
  nil
end

# src/grammar/genericParseStatus.ts: collectFields
def psg_collect_fields(fields, out)
  fields.to_a.each do |(name, node)|
    if (((!psg_k_grammar_owned_nodes.include?(name) || node.equal?(:psg_null)) || !(psg_typeof(node) == 'object')) || node.is_a?(Array))
      psg_collect(node, name, out)
      next
    end
    node.to_a.each do |(childKey, child)|
      if !psg_k_provenance_copies.include?(childKey)
        psg_collect(child, childKey, out)
      end
    end
  end
  nil
end

# src/genericStructural.ts: commaKv
def psg_comma_kv(raw)
  parts = prefix = syslog = pri = value = tokens = fields = segment = eq = key = value_2 = previous = generic = nil
  parts = psg_split_escaped_2(raw, ',')
  if (!psg_t(parts) || (parts.length < 3))
    return :psg_null
  end
  prefix = psg_replace(parts[0], /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
  syslog = {}
  pri = (/\A<([0-9]{1,3})>/.match(prefix) || :psg_null)
  if psg_t(pri)
    value = psg_num(pri[1])
    if ((!psg_integer?(value) || (value < 0)) || (value > 191))
      return :psg_null
    end
    syslog['pri'] = pri[1]
    prefix = psg_replace(psg_slice(prefix, psg_len(pri[0])), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
  end
  if !/(?:\A|[ \t])[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[ \t]|\z)/.match?(prefix)
    return :psg_null
  end
  tokens = psg_map(psg_split(prefix, /[ \t]+/), lambda { |value_3| (((psg_len(value_3) > 1) && [':', ','].include?(psg_at(value_3, (psg_len(value_3) - 1)))) ? psg_slice(value_3, 0, (-1)) : value_3) })
  if (((tokens.length < 8) || (tokens.length > 64)) || psg_some(tokens, lambda { |value_4| ((psg_len(value_4) < 1) || (value_4.bytesize > 256)) }))
    return :psg_null
  end
  fields = {}
  psg_slice(parts, 1).each do |rawSegment|
    segment = psg_replace(rawSegment, /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if !psg_t(segment)
      next
    end
    eq = psg_index(segment, '=')
    if (eq <= 0)
      return :psg_null
    end
    key = psg_replace(psg_slice(segment, 0, eq), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (!/\A[A-Za-z_][A-Za-z0-9_.\#\/\-]{0,127}\z/.match?(key) || !psg_source_key_safe(key))
      return :psg_null
    end
    value_2 = psg_replace(psg_slice(segment, (eq + 1)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if ((psg_len(value_2) >= 2) && ((value_2.start_with?('"') && value_2.end_with?('"')) || (value_2.start_with?('\'') && value_2.end_with?('\''))))
      value_2 = psg_slice(value_2, 1, (-1))
    elsif (((value_2.start_with?('"') || value_2.start_with?('\'')) || value_2.end_with?('"')) || value_2.end_with?('\''))
      return :psg_null
    end
    previous = fields[key]
    fields[key] = (previous.nil? ? value_2 : (previous.is_a?(Array) ? [*previous, value_2] : [previous, value_2]))
  end
  if (fields.keys.length < 2)
    return :psg_null
  end
  generic = {'mode' => 'comma_kv'}
  psg_for_each(tokens, lambda { |value_5, index|
  generic[('prefix_' + psg_pad_start(psg_str((index + 1)), 3, '0'))] = value_5
  nil
})
  generic['kv'] = fields
  return (psg_t(syslog.keys.length) ? {'syslog' => syslog, 'generic' => generic} : {'generic' => generic})
end

# src/syslogEnvelope.ts: decomposePri
def psg_decompose_pri(priText = nil)
  pri = nil
  if priText.nil?
    return {}
  end
  if !/\A[0-9]{1,3}\z/.match?(priText)
    return :psg_null
  end
  pri = psg_num(priText)
  if ((!psg_integer?(pri) || (pri < 0)) || (pri > 191))
    return :psg_null
  end
  return {'pri' => priText, 'facility' => psg_floor_div(pri, 8), 'severity' => psg_mod(pri, 8)}
end

# src/syslogEnvelope.ts: decorateMessage
def psg_decorate_message(envelope)
  body = tag = nil
  body = envelope['message']
  tag = (/\A([A-Za-z0-9_.@\/\-]{1,128})(?:\[([0-9]{1,10})\])?:[ \t]*((?m:.)*)\z/.match(body) || :psg_null)
  if ((!psg_t(tag) || (tag[1] == 'CEF')) || (tag[1] == 'LEEF'))
    return envelope
  end
  return {}.merge!(envelope).merge!({'appname' => tag[1]}).merge!((psg_t(tag[2]) ? {'procid' => tag[2]} : {})).merge!({'message' => tag[3]})
end

# src/genericStructural.ts: delimitedCommaKv
def psg_delimited_comma_kv(raw)
  parts = fields = prefix = parsed = safe = index = segment = eq = before = key = cut = suffix = value = previous = prefixTokens = nil
  if (raw.bytesize > 8192)
    return :psg_null
  end
  parts = psg_split_escaped_2(raw, ',')
  if (!psg_t(parts) || (parts.length < 4))
    return :psg_null
  end
  fields = {}
  prefix = ''
  parsed = 0
  safe = /\A[A-Za-z0-9][A-Za-z0-9 ._:\/()\#\-]{0,127}\z/
  index = 0
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else index += 1 end
    break unless (index < parts.length)
    segment = psg_replace(psg_at(parts, index), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if !psg_t(segment)
      next
    end
    eq = psg_index(segment, '=')
    if (eq <= 0)
      return :psg_null
    end
    before = psg_replace(psg_slice(segment, 0, eq), /[ \t\n\x0b\f\r]+\z/, false, '')
    key = psg_replace(before, /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if (index == 0)
      cut = [psg_rindex(before, ': '), psg_rindex(before, '. ')].max
      if (cut >= 0)
        suffix = psg_replace(psg_slice(before, (cut + 2)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
        if safe.match?(suffix)
          key = suffix
          prefix = psg_replace(psg_slice(before, 0, (cut + 2)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
        end
      end
    end
    if (!safe.match?(key) || !psg_source_key_safe(key))
      return :psg_null
    end
    value = psg_replace(psg_slice(segment, (eq + 1)), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    if ((psg_len(value) >= 2) && ((value.start_with?('"') && value.end_with?('"')) || (value.start_with?('\'') && value.end_with?('\''))))
      value = psg_slice(value, 1, (-1))
    elsif (((value.start_with?('"') || value.start_with?('\'')) || value.end_with?('"')) || value.end_with?('\''))
      return :psg_null
    end
    previous = fields[key]
    fields[key] = (previous.nil? ? value : (previous.is_a?(Array) ? [*previous, value] : [previous, value]))
    parsed += 1
  end
  if (parsed < 4)
    return :psg_null
  end
  prefixTokens = (psg_t(prefix) ? psg_map(psg_split(prefix, /[ \t]+/), lambda { |value_2| (((psg_len(value_2) > 1) && [':', ','].include?(psg_at(value_2, (psg_len(value_2) - 1)))) ? psg_slice(value_2, 0, (-1)) : value_2) }) : [])
  if ((prefixTokens.length > 64) || psg_some(prefixTokens, lambda { |value_3| (!psg_t(value_3) || (value_3.bytesize > 256)) }))
    return :psg_null
  end
  return {'generic' => {'mode' => 'delimited_kv', 'delimiter' => ',', 'prefix_tokens' => prefixTokens, 'fields' => fields}}
end

# src/genericStructural.ts: dualTimestampSessionProfile
def psg_dual_timestamp_session_profile(raw)
  match = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255}) +1 +([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+\-][0-9]{2}:[0-9]{2})) +([^ \t\n\r\f\x0b]{1,255}) +([A-Za-z0-9_.\-]{1,64}): +- +- +- +([0-9]{4}-[0-9]{2}-[0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +- +([^ \t\n\r\f\x0b]{1,255}) +- +\[([^\]\r\n]{1,255})\] +((?m:.)+?) +- +((?m:.)+)\z/.match(raw) || :psg_null)
  if (!psg_t(match) || !psg_valid_bsd_clock(match[1], match[2], match[3]))
    return :psg_null
  end
  if (!psg_iso_timestamp_ok(match[5]) || !psg_valid_iso_pri_clock(match[8], match[9], 'Z'))
    return :psg_null
  end
  return {'syslog' => {'month' => match[1], 'day' => match[2], 'time' => match[3], 'hostname' => match[4], 'version' => '1', 'timestamp' => match[5], 'source' => match[6], 'app_tag' => match[7]}, 'session_envelope' => {'source_raw' => raw, 'event_date' => match[8], 'event_time' => match[9], 'node' => match[10], 'client' => match[11], 'identity' => match[12], 'message' => match[13]}}
end

# src/syslogEnvelope.ts: envelopeToSyslogFields
def psg_envelope_to_syslog_fields(envelope)
  fields = value = nil
  fields = {'variant' => envelope['variant'], 'confidence' => envelope['confidence']}
  ['pri', 'facility', 'severity', 'version', 'timestamp', 'month', 'day', 'year', 'time', 'timezone', 'hostname', 'appname', 'procid', 'msgid', 'structuredData'].each do |key|
    value = envelope[key]
    if !value.nil?
      fields[key] = value
    end
  end
  return fields
end

# src/genericStructural.ts: envelopedFamilyClaim
def psg_enveloped_family_claim(raw)
  envelope = nil
  envelope = psg_parse_syslog_envelope(raw)
  return ((psg_t(envelope) && (envelope['variant'] != 'colon_date')) ? psg_structured_family_claim(envelope['message']) : :psg_null)
end

# src/genericStructural.ts: envelopedJsonDeclined
def psg_enveloped_json_declined(raw)
  envelope = message = nil
  envelope = psg_parse_syslog_envelope(raw)
  if (!psg_t(envelope) || (envelope['variant'] == 'colon_date'))
    return false
  end
  message = envelope['message']
  if (!/\A\{[ \t]*"(?:[^"\\]|\\[^\n\r\u2028\u2029])*"[ \t]*:/.match?(message) || !/\}[ \t\n\r]*\z/.match?(message))
    return false
  end
  return psg_bounded_envelope_json(message).equal?(:psg_null)
end

# src/genericStructural.ts: extractGenericStructural
def psg_extract_generic_structural(raw, profile = nil, familyGrammar = nil)
  unsupportedVersion = includesLeef = includesSyslog = fields = envelope = parsed = body = claim = parsed_2 = enveloped = fields_2 = generic = fields_3 = nil
  if /[\x00\x0a-\x0d\x1c-\x1f]/.match?(raw)
    return {'fields' => {}, 'errors' => ['Unsupported physical control separator in Generic Structural source']}
  end
  unsupportedVersion = psg_unsupported_rfc5424_version(raw)
  if !unsupportedVersion.equal?(:psg_null)
    return {'fields' => {}, 'errors' => [(('Unsupported RFC5424 version ' + unsupportedVersion) + ': only VERSION 1 is supported')]}
  end
  includesLeef = ((profile == 'leef2_implicit_tab') || (profile == 'syslog_prefix_kv_leef2_implicit_tab_v1'))
  includesSyslog = ((profile == 'syslog_prefix_kv') || (profile == 'syslog_prefix_kv_leef2_implicit_tab_v1'))
  if (includesLeef && raw.start_with?('LEEF:2.0|'))
    fields = psg_extract_leef2_implicit_tab(raw)
    return (psg_t(fields) ? {'fields' => fields, 'errors' => []} : {'fields' => {}, 'errors' => ['Event does not match the bounded Generic Structural compiler grammar']})
  end
  if (includesLeef && (familyGrammar == 'dedicated'))
    envelope = psg_parse_syslog_envelope(raw)
    if ((psg_t(envelope) && (envelope['variant'] != 'colon_date')) && envelope['message'].start_with?('LEEF:2.0|'))
      parsed = psg_extract_leef2_implicit_tab(envelope['message'])
      if psg_t(parsed)
        body = {'leef_header' => parsed['leef_header'], 'leef_extension' => parsed['leef_extension']}
        return {'fields' => {'syslog' => psg_envelope_to_syslog_fields(envelope), 'body' => body, 'generic' => {'mode' => 'syslog_envelope_leef2_implicit_tab', 'source_raw' => raw, 'message_raw' => envelope['message']}}, 'errors' => []}
      end
    end
  end
  claim = ((familyGrammar == 'dedicated') ? psg_structured_family_claim(raw) : :psg_null)
  if psg_t(claim)
    parsed_2 = psg_extract_structured_family(raw, ((claim == 'CEF') ? 'cef' : 'leef'))
    if psg_t(parsed_2['errors'].length)
      return {'fields' => {}, 'errors' => [(((('The event claims to be ' + claim) + ' but does not match the ') + claim) + ' grammar; it is not read as generic key=value')]}
    end
    return {'fields' => psg_with_body_text({'body' => parsed_2['fields'], 'generic' => {'mode' => ((claim == 'CEF') ? 'structured_family_cef' : 'structured_family_leef'), 'source_raw' => raw}}, ((claim == 'CEF') ? 'cef' : 'leef'), raw), 'errors' => []}
  end
  enveloped = ((familyGrammar == 'dedicated') ? psg_enveloped_family_claim(raw) : :psg_null)
  if psg_t(enveloped)
    fields_2 = psg_syslog_envelope_structured_fallback(raw)
    generic = (psg_null?(psg_t1 = fields_2) ? nil : psg_t1['generic'])
    if ((psg_t(fields_2) && (psg_null?(psg_t2 = generic) ? nil : psg_t2['mode']).is_a?(String)) && psg_k_generic_family_modes.include?(generic['mode']))
      return {'fields' => fields_2, 'errors' => []}
    end
    return {'fields' => {}, 'errors' => [(((('The event claims to be ' + enveloped) + ' inside a Syslog envelope but does not match the ') + enveloped) + ' grammar; it is not read as generic key=value')]}
  end
  if ((familyGrammar == 'dedicated') && psg_enveloped_json_declined(raw))
    return {'fields' => {}, 'errors' => ['The message claims to be a JSON object but the JSON body contract does not read it (not valid JSON, a repeated member name, a number that cannot be kept exactly, or the bounded size); it is not read as free text']}
  end
  fields_3 = (psg_null?(psg_t3 = (psg_null?(psg_t4 = (psg_null?(psg_t5 = (psg_null?(psg_t6 = (psg_null?(psg_t7 = (psg_null?(psg_t8 = (psg_null?(psg_t9 = (psg_null?(psg_t10 = (psg_null?(psg_t11 = (psg_null?(psg_t12 = (psg_null?(psg_t13 = (psg_null?(psg_t14 = (psg_null?(psg_t15 = (psg_null?(psg_t16 = (psg_null?(psg_t17 = (psg_null?(psg_t18 = (psg_null?(psg_t19 = (psg_null?(psg_t20 = (psg_null?(psg_t21 = (psg_null?(psg_t22 = (psg_null?(psg_t23 = (psg_null?(psg_t24 = (psg_null?(psg_t25 = (psg_null?(psg_t26 = psg_short_rfc5424_structured(raw)) ? psg_short_rfc5424_json(raw) : psg_t26)) ? psg_prefixed_json(raw) : psg_t25)) ? psg_iso_pri_mixed(raw) : psg_t24)) ? psg_iso_pri_positional(raw) : psg_t23)) ? psg_asa(raw) : psg_t22)) ? psg_watchguard_profile(raw) : psg_t21)) ? psg_watchguard_message_profile(raw) : psg_t20)) ? psg_watchguard_traffic_monitor_profile(raw) : psg_t19)) ? psg_meraki_profile(raw) : psg_t18)) ? psg_dual_timestamp_session_profile(raw) : psg_t17)) ? psg_bsd_bracket_pid_message_profile(raw) : psg_t16)) ? psg_juniper_legacy_profile(raw) : psg_t15)) ? psg_junos_rfc5424_sd(raw) : psg_t14)) ? psg_bracket_colon_kv(raw) : psg_t13)) ? psg_rfc3164_delimited_comma_kv(raw) : psg_t12)) ? psg_rfc3164_positional_csv(raw) : psg_t11)) ? psg_pri_space_kv(raw) : psg_t10)) ? psg_syslog_envelope_structured_fallback(raw) : psg_t9)) ? psg_comma_kv(raw) : psg_t8)) ? psg_delimited_comma_kv(raw) : psg_t7)) ? psg_space_kv(raw) : psg_t6)) ? psg_bsd_classic_pid_message_profile(raw) : psg_t5)) ? psg_bsd_tagged_message_profile(raw) : psg_t4)) ? (includesSyslog ? psg_syslog_prefixed_key_values(raw) : :psg_null) : psg_t3)
  return (psg_t(fields_3) ? {'fields' => fields_3, 'errors' => []} : {'fields' => {}, 'errors' => ['Event does not match the bounded Generic Structural compiler grammar']})
end

# src/leef2ImplicitTab.ts: extractLeef2ImplicitTab
def psg_extract_leef2_implicit_tab(raw)
  bytes = names = header = cursor = v_end = value = extension = tokens = fields = equal = key = value_2 = nil
  bytes = raw.bytes
  if (((bytes.length > 8192) || /[\x00-\x08\x0a-\x1f\x7f]/.match?(raw)) || !raw.start_with?('LEEF:2.0|'))
    return :psg_null
  end
  if !psg_is_well_formed(raw)
    return :psg_null
  end
  names = ['vendor', 'product', 'product_version', 'event_id']
  header = {'version' => psg_slice(raw, 5, 8)}
  cursor = 9
  names.each do |name|
    v_end = psg_index(raw, '|', cursor)
    if (v_end < 0)
      return :psg_null
    end
    value = psg_slice(raw, cursor, v_end)
    if (((!psg_t(value) || !psg_t(psg_replace(value, ' ', true, ''))) || /[\\\t]/.match?(value)) || (value.bytesize > 256))
      return :psg_null
    end
    header[name] = value
    cursor = (v_end + 1)
  end
  extension = psg_slice(raw, cursor)
  if extension.start_with?("\u{9}")
    extension = psg_slice(extension, 1)
  end
  if (!psg_t(extension) || extension.include?('|'))
    return :psg_null
  end
  tokens = psg_split(extension, "\u{9}")
  if ((tokens.length < 2) || (tokens.length > 55))
    return :psg_null
  end
  fields = {}
  tokens.each do |token|
    equal = psg_index(token, '=')
    if (equal < 1)
      return :psg_null
    end
    key = psg_slice(token, 0, equal)
    value_2 = psg_slice(token, (equal + 1))
    if ((((!/\A[A-Za-z_][A-Za-z0-9_\-]{0,63}\z/.match?(key) || ['__proto__', 'prototype', 'constructor'].include?(key)) || fields.key?(key)) || !psg_t(value_2)) || (value_2.bytesize > 512))
      return :psg_null
    end
    fields[key] = value_2
  end
  return {'leef_header' => header, 'leef_extension' => fields, 'generic' => {'mode' => 'leef2_implicit_tab', 'source_raw' => raw}}
end

# src/syslogEnvelope.ts: fieldTokenValid
def psg_field_token_valid(value, max)
  return ((value == '-') || (((psg_len(value) >= 1) && (psg_len(value) <= max)) && /\A[!-~]+\z/.match?(value)))
end

# src/genericStructural.ts: ipToken
def psg_ip_token(value)
  v4 = sides = groups = nil
  v4 = psg_split(value, '.')
  if ((v4.length == 4) && psg_every(v4, lambda { |part| (/\A[0-9]{1,3}\z/.match?(part) && (psg_num(part) <= 255)) }))
    return true
  end
  if (!/\A[0-9A-Fa-f:]+\z/.match?(value) || value.include?(':::'))
    return false
  end
  sides = psg_split(value, '::')
  if ((sides.length > 2) || psg_some(sides, lambda { |side| (side.start_with?(':') || side.end_with?(':')) }))
    return false
  end
  groups = psg_filter(psg_split(value, ':'), lambda { |part_2| (part_2 != '') })
  if psg_some(groups, lambda { |part_3| (psg_len(part_3) > 4) })
    return false
  end
  return ((sides.length == 2) ? (groups.length <= 7) : (groups.length == 8))
end

# src/genericStructural.ts: isoPriMixed
def psg_iso_pri_mixed(raw)
  head = pri = body = values = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  head = (/\A<([0-9]{1,3})>([0-9]{4}-[0-9]{2}-[0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +(Z|[+\-][0-9]{4}|[+\-][0-9]{2}:[0-9]{2}) +/.match(raw) || :psg_null)
  if !psg_t(head)
    return :psg_null
  end
  pri = psg_num(head[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !psg_valid_iso_pri_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  body = psg_scan_profile_tokens(raw, psg_len(head[0]))
  if (!psg_t(body) || (body['tokens'].length < 16))
    return :psg_null
  end
  values = [*body['tokens']]
  body['kv'].values.each do |value|
    if value.is_a?(Array)
      value.each do |item|
        values.push(psg_str(item))
      end
    else
      values.push(psg_str(value))
    end
  end
  if (psg_filter(values, method(:psg_ip_token)).length < 2)
    return :psg_null
  end
  return {'syslog' => {'pri' => head[1], 'date' => head[2], 'time' => head[3], 'timezone' => head[4]}, 'generic' => body}
end

# src/genericStructural.ts: isoPriPositional
def psg_iso_pri_positional(raw)
  head = pri = body = anchors = portLike = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  head = (/\A<([0-9]{1,3})>([0-9]{4}-[0-9]{2}-[0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +(Z|[+\-][0-9]{4}|[+\-][0-9]{2}:[0-9]{2}) +/.match(raw) || :psg_null)
  if !psg_t(head)
    return :psg_null
  end
  pri = psg_num(head[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !psg_valid_iso_pri_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  body = psg_scan_profile_tokens(raw, psg_len(head[0]))
  if ((!psg_t(body) || (body['tokens'].length < 8)) || (body['tokens'].length > 64))
    return :psg_null
  end
  anchors = psg_slice(body['tokens'], 0, 5)
  if (((anchors.length < 5) || psg_some(anchors, lambda { |value| !/\A[A-Za-z0-9_.:\/\-]{1,128}\z/.match?(value) })) || !/\A[A-Z][A-Z0-9_]{1,15}\z/.match?(body['tokens'][1]))
    return :psg_null
  end
  portLike = lambda { |value_2| (!!psg_t(value_2) && /\A[0-9]{1,5}\z/.match?(value_2)) }
  if ((((body['tokens'].length >= 16) && portLike.call(body['tokens'][5])) && portLike.call(body['tokens'][7])) && (!psg_ip_token(body['tokens'][4]) || !psg_ip_token(body['tokens'][6])))
    return :psg_null
  end
  return {'syslog' => {'pri' => head[1], 'date' => head[2], 'time' => head[3], 'timezone' => head[4]}, 'generic' => {'mode' => 'iso_pri_positional', 'source_raw' => raw}.merge!(body)}
end

# src/genericStructural.ts: isoTimestampOk
def psg_iso_timestamp_ok(value)
  match = year = month = day = leap = nil
  match = (/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:Z|[+\-]([0-9]{2}):([0-9]{2}))?\z/.match(value) || :psg_null)
  if !psg_t(match)
    return false
  end
  year = psg_num(match[1])
  month = psg_num(match[2])
  day = psg_num(match[3])
  if (((((year < 1) || (year > 9999)) || (month < 1)) || (month > 12)) || (day < 1))
    return false
  end
  leap = ((psg_mod(year, 4) == 0) && ((psg_mod(year, 100) != 0) || (psg_mod(year, 400) == 0)))
  if (day > psg_at([31, (leap ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31], (month - 1)))
    return false
  end
  if (((psg_num(match[4]) > 23) || (psg_num(match[5]) > 59)) || (psg_num(match[6]) > 59))
    return false
  end
  return (match[7].nil? || ((psg_num(match[7]) <= 23) && (psg_num(match[8]) <= 59)))
end

# src/genericStructural.ts: juniperLegacyProfile
def psg_juniper_legacy_profile(raw)
  head = after = event = body = nil
  head = (/\A([A-Z][a-z]{2}) +([0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]+) +([^: \t\n\r\f\x0b]{1,128}): +/.match(raw) || :psg_null)
  if ((!psg_t(head) || (head[5] != 'RT_FLOW')) || !psg_valid_bsd_clock(head[1], head[2], head[3]))
    return :psg_null
  end
  after = psg_slice(raw, psg_len(head[0]))
  event = (/\A(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.match(after) || :psg_null)
  if !psg_t(event)
    return :psg_null
  end
  body = psg_scan_profile_tokens(raw, (psg_len(head[0]) + psg_len(event[0])))
  if (!psg_t(body) || !psg_some(body['tokens'], lambda { |value| /\A[^\/ \t\n\r\f\x0b]+\/[0-9]{1,5}->[^\/ \t\n\r\f\x0b]+\/[0-9]{1,5}\z/.match?(value) }))
    return :psg_null
  end
  return {'syslog' => {'month' => head[1], 'day' => head[2], 'time' => head[3], 'hostname' => head[4], 'app_tag' => head[5]}, 'juniper' => {'event' => event[1]}.merge!(body)}
end

# src/genericStructural.ts: juniperRtFlowBody
def psg_juniper_rt_flow_body(text)
  event = body = nil
  event = (/\A(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.match(text) || :psg_null)
  if !psg_t(event)
    return :psg_null
  end
  body = psg_scan_profile_tokens(text, psg_len(event[0]))
  if (!psg_t(body) || !psg_some(body['tokens'], lambda { |value| /\A[^\/ \t\n\r\f\x0b]+\/[0-9]{1,5}->[^\/ \t\n\r\f\x0b]+\/[0-9]{1,5}\z/.match?(value) }))
    return :psg_null
  end
  return {'event' => event[1]}.merge!(body)
end

# src/genericStructural.ts: junosRfc5424Sd
def psg_junos_rfc5424_sd(raw)
  match = pri = structuredDataRaw = inner = head = pos = fields = keyMatch = key = value = closed = ch = v_next = safe = nil
  match = (/\A<([0-9]{1,3})>(1) ([^ \t\n\r\f\x0b]+) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[junos@[A-Za-z0-9.:\-]{1,64}(?: [^\]]*)?\])\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  pri = psg_num(match[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !psg_valid_rfc3339(match[3]))
    return :psg_null
  end
  structuredDataRaw = match[8]
  if (structuredDataRaw.bytesize > 8192)
    return :psg_null
  end
  inner = psg_slice(structuredDataRaw, 1, (-1))
  head = (/\Ajunos@[A-Za-z0-9.:\-]{1,64}/.match(inner) || :psg_null)
  if !psg_t(head)
    return :psg_null
  end
  pos = psg_len(head[0])
  fields = {}
  while (pos < psg_len(inner))
    if (psg_at(inner, pos) != ' ')
      return :psg_null
    end
    pos += 1
    keyMatch = (/\A[A-Za-z_][A-Za-z0-9_\-]{0,63}/.match(psg_slice(inner, pos)) || :psg_null)
    if !psg_t(keyMatch)
      return :psg_null
    end
    key = keyMatch[0]
    pos += psg_len(key)
    if (psg_slice(inner, pos, (pos + 2)) != '="')
      return :psg_null
    end
    pos += 2
    value = ''
    closed = false
    while (pos < psg_len(inner))
      ch = psg_at(inner, pos)
      if (ch == '"')
        closed = true
        pos += 1
        break
      end
      if (ch == '\\')
        v_next = psg_at(inner, (pos + 1))
        if (v_next.nil? || !['"', '\\', ']'].include?(v_next))
          return :psg_null
        end
        value += v_next
        pos += 2
        next
      end
      if ((psg_char_code_at(ch, 0) < 32) || (psg_char_code_at(ch, 0) == 127))
        return :psg_null
      end
      value += ch
      pos += 1
    end
    if !closed
      return :psg_null
    end
    safe = psg_replace(key, '-', true, '_')
    if ((!psg_source_key_safe(key) || !psg_source_key_safe(safe)) || fields.key?(safe))
      return :psg_null
    end
    fields[safe] = value
    if (fields.keys.length > 64)
      return :psg_null
    end
  end
  if (fields.keys.length < 1)
    return :psg_null
  end
  return {'syslog' => {'pri' => match[1], 'version' => match[2], 'timestamp' => match[3], 'hostname' => match[4], 'appname' => match[5], 'procid' => match[6], 'msgid' => match[7], 'structured_data_raw' => structuredDataRaw}, 'junos_sd' => fields}
end

# src/syslogEnvelope.ts: leapYear
def psg_leap_year(year)
  return ((psg_mod(year, 4) == 0) && ((psg_mod(year, 100) != 0) || (psg_mod(year, 400) == 0)))
end

# src/syslogEnvelope.ts: looksLikeMalformedTimestamp
def psg_looks_like_malformed_timestamp(rest)
  return ((/\A[A-Z][a-z]{2} +[0-9]{1,2} +/.match?(rest) || /\A[0-9]{4}[\-\/:][0-9]{2}[\-\/:][0-9]{2}/.match?(rest)) || /\A[0-9]{1,3} +[0-9]{4}-[0-9]{2}-[0-9]{2}T/.match?(rest))
end

# src/genericStructural.ts: merakiProfile
def psg_meraki_profile(raw)
  head = kv = generic = pos = pairs = rest = label = pair = header = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  head = (/\A([0-9]{9,10}\.[0-9]{1,9}) ([A-Za-z0-9_.\-]{1,64}) (flows|firewall|vpn_firewall|cellular_firewall|bridge_anyconnect_client_vpn_firewall|urls|ids-alerts|security_event)(?: ([a-z][a-z_]{0,31}))? /.match(raw) || :psg_null)
  if !psg_t(head)
    return :psg_null
  end
  kv = {}
  generic = {'mode' => psg_k_meraki_record_modes[head[3]], 'source_raw' => raw, 'kv' => kv}
  pos = psg_len(head[0])
  pairs = 0
  while (pos < psg_len(raw))
    rest = psg_slice(raw, pos)
    label = (/\A(pattern|message|request): ([^\n\r\u2028\u2029]+)\z/.match(rest) || :psg_null)
    if psg_t(label)
      generic[label[1]] = label[2]
      break
    end
    pair = (/\A([A-Za-z_][A-Za-z0-9_.\-]{0,63})=([^ ]*)(?: |\z)/.match(rest) || :psg_null)
    if ((!psg_t(pair) || !psg_source_key_safe(pair[1])) || kv.key?(pair[1]))
      return :psg_null
    end
    pairs += 1
    if (pairs > 100)
      return :psg_null
    end
    kv[pair[1]] = pair[2]
    pos += psg_len(pair[0])
  end
  if (!kv['src'].is_a?(String) || !kv['dst'].is_a?(String))
    return :psg_null
  end
  header = {'epoch' => head[1], 'device' => head[2], 'record_type' => head[3]}
  if !head[4].nil?
    header['event_type'] = head[4]
  end
  return {'meraki_header' => header, 'generic' => generic}
end

# src/genericStructural.ts: panosNamedFields
def psg_panos_named_fields(values)
  return (psg_null?(psg_t1 = (psg_null?(psg_t2 = psg_panos_traffic_fields(values)) ? psg_panos_threat_fields(values) : psg_t2)) ? psg_panos_system_fields(values) : psg_t1)
end

# src/genericStructural.ts: panosNamedMode
def psg_panos_named_mode(values)
  if psg_t(psg_panos_traffic_fields(values))
    return 'panos_traffic_csv'
  end
  if psg_t(psg_panos_threat_fields(values))
    return 'panos_threat_csv'
  end
  if psg_t(psg_panos_system_fields(values))
    return 'panos_system_csv'
  end
  return :psg_null
end

# src/genericStructural.ts: panosPositionalCsvBody
def psg_panos_positional_csv_body(text)
  values = received = columns = nil
  values = psg_positional_csv_values(text)
  if ((!psg_t(values) || (values.length < 7)) || (values.length > 150))
    return :psg_null
  end
  if !/\A[0-9]{0,10}\z/.match?((psg_null?(psg_t1 = values[0]) ? '' : psg_t1))
    return :psg_null
  end
  received = (/\A([0-9]{4})\/([0-9]{2})\/([0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?)\z/.match((psg_null?(psg_t2 = values[1]) ? '' : psg_t2)) || :psg_null)
  if (!psg_t(received) || !psg_valid_iso_pri_clock(((((received[1] + '-') + received[2]) + '-') + received[3]), received[4], 'Z'))
    return :psg_null
  end
  if !/\A[A-Za-z0-9_.:\-]{4,64}\z/.match?((psg_null?(psg_t3 = values[2]) ? '' : psg_t3))
    return :psg_null
  end
  if !/\A(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE)\z/.match?((psg_null?(psg_t4 = values[3]) ? '' : psg_t4))
    return :psg_null
  end
  columns = {}
  psg_for_each(values, lambda { |value, index|
  columns[('column_' + psg_str(index))] = value
  nil
})
  return columns
end

# src/genericStructural.ts: panosSystemFields
def psg_panos_system_fields(values)
  datetime = fields = nil
  if ((values.length < 15) || (values[3] != 'SYSTEM'))
    return :psg_null
  end
  datetime = /\A[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\z/
  if (((!datetime.match?((psg_null?(psg_t1 = values[1]) ? '' : psg_t1)) || !datetime.match?((psg_null?(psg_t2 = values[6]) ? '' : psg_t2))) || !/\A[A-Za-z0-9_.\-]{1,64}\z/.match?((psg_null?(psg_t3 = values[8]) ? '' : psg_t3))) || !/\A(?:informational|low|medium|high|critical)\z/.match?((psg_null?(psg_t4 = values[13]) ? '' : psg_t4)))
    return :psg_null
  end
  fields = {}
  psg_for_each(values, lambda { |value, index|
  fields[(psg_null?(psg_t5 = psg_at(psg_k_panos_system, index)) ? ('column_' + psg_str(index)) : psg_t5)] = value
  nil
})
  return fields
end

# src/genericStructural.ts: panosThreatFields
def psg_panos_threat_fields(values)
  datetime = ip = validIp = value = fields = nil
  if ((values.length < 42) || (values[3] != 'THREAT'))
    return :psg_null
  end
  datetime = /\A[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\z/
  ip = /\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/
  validIp = lambda { |value_2| (ip.match?(value_2) && psg_every(psg_split(value_2, '.'), lambda { |part| (psg_num(part) <= 255) })) }
  if ((((((!datetime.match?((psg_null?(psg_t1 = values[1]) ? '' : psg_t1)) || !datetime.match?((psg_null?(psg_t2 = values[6]) ? '' : psg_t2))) || !datetime.match?((psg_null?(psg_t3 = values[21]) ? '' : psg_t3))) || !validIp.call((psg_null?(psg_t4 = values[7]) ? '' : psg_t4))) || !validIp.call((psg_null?(psg_t5 = values[8]) ? '' : psg_t5))) || !validIp.call((psg_null?(psg_t6 = values[9]) ? '' : psg_t6))) || !validIp.call((psg_null?(psg_t7 = values[10]) ? '' : psg_t7)))
    return :psg_null
  end
  [24, 25, 26, 27].each do |index|
    value = (psg_null?(psg_t8 = psg_at(values, index)) ? '' : psg_t8)
    if (!/\A[0-9]{1,5}\z/.match?(value) || (psg_num(value) > 65535))
      return :psg_null
    end
  end
  if (((!/\A[A-Za-z0-9_.\-]{1,24}\z/.match?((psg_null?(psg_t9 = values[29]) ? '' : psg_t9)) || !/\A[A-Za-z0-9_. \-]{1,64}\z/.match?((psg_null?(psg_t10 = values[30]) ? '' : psg_t10))) || !/\A(?:informational|low|medium|high|critical)\z/.match?((psg_null?(psg_t11 = values[34]) ? '' : psg_t11))) || !/\A(?:client-to-server|server-to-client|0|1)\z/.match?((psg_null?(psg_t12 = values[35]) ? '' : psg_t12)))
    return :psg_null
  end
  fields = {}
  psg_for_each(values, lambda { |value_3, index_2|
  fields[(psg_null?(psg_t13 = psg_at(psg_k_panos_threat, index_2)) ? ('column_' + psg_str(index_2)) : psg_t13)] = value_3
  nil
})
  return fields
end

# src/genericStructural.ts: panosTrafficFields
def psg_panos_traffic_fields(values)
  datetime = ip = validIp = value = names = fields = nil
  if ((values.length < 53) || (values[3] != 'TRAFFIC'))
    return :psg_null
  end
  datetime = /\A[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\z/
  ip = /\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/
  validIp = lambda { |value_2| (ip.match?(value_2) && psg_every(psg_split(value_2, '.'), lambda { |part| (psg_num(part) <= 255) })) }
  if (((((((!datetime.match?((psg_null?(psg_t1 = values[1]) ? '' : psg_t1)) || !datetime.match?((psg_null?(psg_t2 = values[6]) ? '' : psg_t2))) || !datetime.match?((psg_null?(psg_t3 = values[21]) ? '' : psg_t3))) || !datetime.match?((psg_null?(psg_t4 = values[35]) ? '' : psg_t4))) || !validIp.call((psg_null?(psg_t5 = values[7]) ? '' : psg_t5))) || !validIp.call((psg_null?(psg_t6 = values[8]) ? '' : psg_t6))) || !validIp.call((psg_null?(psg_t7 = values[9]) ? '' : psg_t7))) || !validIp.call((psg_null?(psg_t8 = values[10]) ? '' : psg_t8)))
    return :psg_null
  end
  [24, 25, 26, 27].each do |index|
    value = (psg_null?(psg_t9 = psg_at(values, index)) ? '' : psg_t9)
    if (!/\A[0-9]{1,5}\z/.match?(value) || (psg_num(value) > 65535))
      return :psg_null
    end
  end
  if (!/\A[A-Za-z0-9_.\-]{1,24}\z/.match?((psg_null?(psg_t10 = values[29]) ? '' : psg_t10)) || !/\A[A-Za-z0-9_. \-]{1,64}\z/.match?((psg_null?(psg_t11 = values[30]) ? '' : psg_t11)))
    return :psg_null
  end
  names = ((values.length >= 54) ? psg_k_panos_traffic_54 : psg_k_panos_traffic_53)
  fields = {}
  psg_for_each(values, lambda { |value_3, index_2|
  fields[(psg_null?(psg_t12 = psg_at(names, index_2)) ? ('field_' + psg_str(index_2)) : psg_t12)] = value_3
  nil
})
  return fields
end

# src/syslogEnvelope.ts: parseBsd
def psg_parse_bsd(pri = nil, rest)
  yearBefore = yearAfter = classic = nil
  yearBefore = (/\A([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{4}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/.match(rest) || :psg_null)
  if (((psg_t(yearBefore) && psg_valid_bsd_timestamp(yearBefore[1], yearBefore[2], yearBefore[4])) && (psg_num(yearBefore[3]) >= 1900)) && (psg_num(yearBefore[3]) <= 9999))
    return psg_decorate_message({'variant' => 'rfc3164_year_before_time', 'confidence' => 'strong'}.merge!(psg_with_pri(pri)).merge!({'month' => yearBefore[1], 'day' => yearBefore[2], 'year' => yearBefore[3], 'time' => yearBefore[4], 'hostname' => yearBefore[5], 'message' => (psg_null?(psg_t1 = yearBefore[6]) ? '' : psg_t1)}))
  end
  yearAfter = (/\A([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +([0-9]{4}) +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/.match(rest) || :psg_null)
  if (((psg_t(yearAfter) && psg_valid_bsd_timestamp(yearAfter[1], yearAfter[2], yearAfter[3])) && (psg_num(yearAfter[4]) >= 1900)) && (psg_num(yearAfter[4]) <= 9999))
    return psg_decorate_message({'variant' => 'rfc3164_year_after_time', 'confidence' => 'strong'}.merge!(psg_with_pri(pri)).merge!({'month' => yearAfter[1], 'day' => yearAfter[2], 'time' => yearAfter[3], 'year' => yearAfter[4], 'hostname' => yearAfter[5], 'message' => (psg_null?(psg_t2 = yearAfter[6]) ? '' : psg_t2)}))
  end
  classic = (/\A([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/.match(rest) || :psg_null)
  if (psg_t(classic) && psg_valid_bsd_timestamp(classic[1], classic[2], classic[3]))
    return psg_decorate_message({'variant' => 'rfc3164', 'confidence' => 'strict'}.merge!(psg_with_pri(pri)).merge!({'month' => classic[1], 'day' => classic[2], 'time' => classic[3], 'hostname' => classic[4], 'message' => (psg_null?(psg_t3 = classic[5]) ? '' : psg_t3)}))
  end
  return :psg_null
end

# src/syslogEnvelope.ts: parseColonDate
def psg_parse_colon_date(pri = nil, rest)
  match = nil
  match = (/\A([0-9]{4}):([0-9]{2}):([0-9]{2})-([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?) +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/.match(rest) || :psg_null)
  if ((!psg_t(match) || !psg_valid_calendar_date(psg_num(match[1]), psg_num(match[2]), psg_num(match[3]))) || !psg_valid_clock(match[4]))
    return :psg_null
  end
  return psg_decorate_message({'variant' => 'colon_date', 'confidence' => 'strong'}.merge!(psg_with_pri(pri)).merge!({'year' => match[1], 'timestamp' => (match[1] + ':' + match[2] + ':' + match[3] + '-' + match[4]), 'time' => match[4], 'hostname' => match[5], 'message' => (psg_null?(psg_t1 = match[6]) ? '' : psg_t1)}))
end

# src/genericStructural.ts: parseJsonBody
def psg_parse_json_body(text)
  value = nil
  value = nil
  begin
    value = psg_json_parse(text)
  rescue StandardError
    return nil
  end
  return (((psg_has_duplicate_json_object_keys(text) || psg_has_unsafe_json_numbers(text)) || !psg_json_source_value_valid(value)) ? nil : value)
end

# src/syslogEnvelope.ts: parseRfc3339Loose
def psg_parse_rfc3339_loose(pri = nil, rest)
  match = nil
  match = (/\A([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?) +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/.match(rest) || :psg_null)
  if (!psg_t(match) || !psg_valid_iso_timestamp(match[1], false))
    return :psg_null
  end
  return psg_decorate_message({'variant' => 'rfc3339_loose', 'confidence' => 'strong'}.merge!(psg_with_pri(pri)).merge!({'timestamp' => match[1], 'hostname' => match[2], 'message' => (psg_null?(psg_t1 = match[3]) ? '' : psg_t1)}))
end

# src/syslogEnvelope.ts: parseRfc5424
def psg_parse_rfc5424(pri = nil, rest)
  match = version = timestamp = hostname = appname = procid = msgid = sd = priParts = nil
  if pri.nil?
    return :psg_null
  end
  match = (/\A([1-9][0-9]{0,2}) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +((?m:.)*)\z/.match(rest) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  version = match[1]
  timestamp = match[2]
  hostname = match[3]
  appname = match[4]
  procid = match[5]
  msgid = match[6]
  if !psg_is_supported_rfc5424_version(version)
    return :psg_null
  end
  if ((((!((timestamp == '-') || psg_valid_iso_timestamp(timestamp, true)) || !psg_field_token_valid(hostname, 255)) || !psg_field_token_valid(appname, 48)) || !psg_field_token_valid(procid, 128)) || !psg_field_token_valid(msgid, 32))
    return :psg_null
  end
  sd = psg_parse_structured_data(match[7])
  if !psg_t(sd)
    return :psg_null
  end
  priParts = psg_decompose_pri(pri)
  if !psg_t(priParts)
    return :psg_null
  end
  return {'variant' => 'rfc5424', 'confidence' => 'strict'}.merge!(priParts).merge!({'version' => version}).merge!(((timestamp != '-') ? {'timestamp' => timestamp} : {})).merge!(((hostname != '-') ? {'hostname' => hostname} : {})).merge!(((appname != '-') ? {'appname' => appname} : {})).merge!(((procid != '-') ? {'procid' => procid} : {})).merge!(((msgid != '-') ? {'msgid' => msgid} : {})).merge!({'structuredData' => sd['structuredData'], 'message' => sd['message']})
end

# src/syslogEnvelope.ts: parseSeparatedDate
def psg_parse_separated_date(pri = nil, rest, slash)
  match = year = month = day = time = zone = nil
  match = ((slash ? /\A([0-9]{4})\/([0-9]{2})\/([0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?)(?: +(Z|[+\-][0-9]{2}:?[0-9]{2}))? +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/ : /\A([0-9]{4})-([0-9]{2})-([0-9]{2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?)(?: +(Z|[+\-][0-9]{2}:?[0-9]{2}))? +([^ \t\n\r\f\x0b]{1,255})(?: +((?m:.)*))?\z/).match(rest) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  year = psg_num(match[1])
  month = psg_num(match[2])
  day = psg_num(match[3])
  time = match[4]
  zone = match[5]
  if ((!psg_valid_calendar_date(year, month, day) || !psg_valid_clock(time)) || (psg_t(zone) && !psg_valid_zone(zone)))
    return :psg_null
  end
  return psg_decorate_message({'variant' => (slash ? 'slash_date' : 'iso_space'), 'confidence' => 'strong'}.merge!(psg_with_pri(pri)).merge!({'year' => match[1], 'timestamp' => (((slash ? (match[1] + '/' + match[2] + '/' + match[3]) : (match[1] + '-' + match[2] + '-' + match[3])) + ' ') + time), 'time' => time}).merge!((psg_t(zone) ? {'timezone' => zone} : {})).merge!({'hostname' => match[6], 'message' => (psg_null?(psg_t1 = match[7]) ? '' : psg_t1)}))
end

# src/syslogEnvelope.ts: parseStructuredData
def psg_parse_structured_data(input)
  scanned = nil
  scanned = psg_scan_structured_data(input)
  return (psg_t(scanned) ? {'structuredData' => scanned['structured'], 'message' => (psg_null?(psg_t1 = scanned['message']) ? '' : psg_t1)} : :psg_null)
end

# src/syslogEnvelope.ts: parseSyslogEnvelope
def psg_parse_syslog_envelope(raw)
  split = rest = rfc5424 = bsd = rfc3339 = iso = slash = colon = nil
  if (((!psg_t(raw) || raw.include?("\u{0}")) || (psg_utf8_size(raw) > 8192)) || /[\r\n]/.match?(raw))
    return :psg_null
  end
  split = psg_split_pri(raw)
  if !psg_t(split)
    return :psg_null
  end
  rest = psg_replace(split['rest'], /\A[ \t\n\r\f\x0b]+/, false, '')
  if !psg_t(rest)
    return :psg_null
  end
  rfc5424 = psg_parse_rfc5424(split['pri'], rest)
  if psg_t(rfc5424)
    return rfc5424
  end
  bsd = psg_parse_bsd(split['pri'], rest)
  if psg_t(bsd)
    return bsd
  end
  rfc3339 = psg_parse_rfc3339_loose(split['pri'], rest)
  if psg_t(rfc3339)
    return rfc3339
  end
  iso = psg_parse_separated_date(split['pri'], rest, false)
  if psg_t(iso)
    return iso
  end
  slash = psg_parse_separated_date(split['pri'], rest, true)
  if psg_t(slash)
    return slash
  end
  colon = psg_parse_colon_date(split['pri'], rest)
  if psg_t(colon)
    return colon
  end
  if (!split['pri'].nil? && !psg_looks_like_malformed_timestamp(rest))
    return {'variant' => 'pri_only', 'confidence' => 'partial'}.merge!(psg_with_pri(split['pri'])).merge!({'message' => rest})
  end
  return :psg_null
end

# src/grammar/lossGuard.ts: positionalCsvUnaccounted
def psg_positional_csv_unaccounted(text, cells)
  return psg_row_unaccounted(text, ',', cells, false)
end

# src/genericStructural.ts: positionalCsvValues
def psg_positional_csv_values(text)
  values = index = token = ch = nil
  if (!psg_t(text) || text.include?("\u{0}"))
    return :psg_null
  end
  values = []
  index = 0
  while true
    token = ''
    if (psg_at(text, index) == '"')
      index += 1
      while true
        if (index >= psg_len(text))
          return :psg_null
        end
        ch = psg_at(text, index)
        if (ch == '"')
          if (psg_at(text, (index + 1)) == '"')
            token += '"'
            index += 2
            next
          end
          index += 1
          break
        end
        token += ch
        index += 1
      end
      if ((index < psg_len(text)) && (psg_at(text, index) != ','))
        return :psg_null
      end
    else
      while ((index < psg_len(text)) && (psg_at(text, index) != ','))
        if (psg_at(text, index) == '"')
          return :psg_null
        end
        token += psg_at(text, index)
        index += 1
      end
    end
    values.push(token)
    if (index >= psg_len(text))
      return values
    end
    index += 1
  end
  nil
end

# src/genericStructural.ts: prefixedJson
def psg_prefixed_json(raw)
  match = body = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A([A-Za-z0-9_.:\/\-]{1,64})[ \t]+(\{(?m:.)*\})\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  body = psg_parse_json_body(match[2])
  if ((!psg_t(body) || body.is_a?(Array)) || !(psg_typeof(body) == 'object'))
    return :psg_null
  end
  return psg_with_body_text({'generic' => {'mode' => 'prefixed_json', 'prefix' => match[1], 'source_raw' => raw}, 'body' => body}, 'json', match[2])
end

# src/genericStructural.ts: priSpaceKv
def psg_pri_space_kv(raw)
  match = pri = parsed = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  match = (/\A<([0-9]{1,3})>([^\n]+)\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  pri = psg_num(match[1])
  if ((!psg_integer?(pri) || (pri < 0)) || (pri > 191))
    return :psg_null
  end
  parsed = psg_space_kv(match[2])
  if ((!psg_t(parsed) || !psg_t(parsed['generic'])) || !(psg_typeof(parsed['generic']) == 'object'))
    return :psg_null
  end
  return {'syslog' => {'pri' => match[1]}, 'generic' => {}.merge!(parsed['generic']).merge!({'source_raw' => raw})}
end

# src/genericStructural.ts: rfc3164DelimitedCommaKv
def psg_rfc3164_delimited_comma_kv(raw)
  head = body = syslog = nil
  if (raw.bytesize > 8192)
    return :psg_null
  end
  head = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255}) +([A-Za-z0-9_.\-]{1,128}): +/.match(raw) || :psg_null)
  if (!psg_t(head) || !psg_valid_bsd_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  if (!head[1].nil? && ((psg_num(head[1]) < 0) || (psg_num(head[1]) > 191)))
    return :psg_null
  end
  body = psg_delimited_comma_kv(psg_slice(raw, psg_len(head[0])))
  if !psg_t(body)
    return :psg_null
  end
  syslog = {'month' => head[2], 'day' => head[3], 'time' => head[4], 'host' => head[5], 'tag' => head[6]}
  if !head[1].nil?
    syslog['pri'] = head[1]
  end
  return {'syslog' => syslog}.merge!(body)
end

# src/genericStructural.ts: rfc3164PositionalCsv
def psg_rfc3164_positional_csv(raw)
  head = body = values = panosLike = ip = ips = securityCategory = panos = panosMode = columns = syslog = nil
  if (raw.bytesize > 8192)
    return :psg_null
  end
  head = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255}) +/.match(raw) || :psg_null)
  if (!psg_t(head) || !psg_valid_bsd_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  if (!head[1].nil? && ((psg_num(head[1]) < 0) || (psg_num(head[1]) > 191)))
    return :psg_null
  end
  body = psg_slice(raw, psg_len(head[0]))
  if /\A[A-Za-z_][A-Za-z0-9_.\-]*=/.match?(body)
    return :psg_null
  end
  values = psg_positional_csv_values(body)
  if (((!psg_t(values) || (values.length < 12)) || (values.length > 100)) || !/\A[0-9]{1,10}\z/.match?((psg_null?(psg_t1 = values[0]) ? '' : psg_t1)))
    return :psg_null
  end
  panosLike = (((((values.length >= 7) && /\A[0-9]{0,10}\z/.match?((psg_null?(psg_t2 = values[0]) ? '' : psg_t2))) && /\A[0-9]{4}\/[0-9]{2}\/[0-9]{2} +[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?\z/.match?((psg_null?(psg_t3 = values[1]) ? '' : psg_t3))) && /\A[A-Za-z0-9_.:\-]{4,64}\z/.match?((psg_null?(psg_t4 = values[2]) ? '' : psg_t4))) && /\A[A-Z][A-Z0-9_]{2,31}\z/.match?((psg_null?(psg_t5 = values[3]) ? '' : psg_t5)))
  if (panosLike && !psg_t(psg_panos_positional_csv_body(body)))
    return :psg_null
  end
  ip = /\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/
  ips = psg_filter(values, lambda { |value| (ip.match?(value) && psg_every(psg_split(value, '.'), lambda { |part| (psg_num(part) <= 255) })) }).length
  securityCategory = psg_some(values, lambda { |value_2| /\A(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION)\z/.match?(value_2) })
  if ((ips < 2) || !securityCategory)
    return :psg_null
  end
  panos = psg_panos_named_fields(values)
  panosMode = psg_panos_named_mode(values)
  columns = {}
  psg_for_each(values, lambda { |value_3, index|
  columns[('column_' + psg_str(index))] = value_3
  nil
})
  syslog = {'month' => head[2], 'day' => head[3], 'time' => head[4], 'hostname' => head[5]}
  if !head[1].nil?
    syslog['pri'] = head[1]
  end
  return psg_with_body_text({'syslog' => syslog, 'generic' => (psg_t(panos) ? {'mode' => panosMode, 'delimiter' => ',', 'source_raw' => raw, 'fields' => panos} : {'mode' => 'rfc3164_positional_csv', 'delimiter' => ',', 'source_raw' => raw, 'columns' => columns})}, 'positional_csv', body)
end

# src/genericStructural.ts: scanProfileTokens
def psg_scan_profile_tokens(raw, start)
  tokens = groups = kv = pos = count = quote = v_begin = cursor = closed = v_end = keyMatch = key = cursor_2 = startValue = v_end_2 = quote_2 = closed_2 = value = previous = v_begin_2 = nil
  if ((((start < 0) || (start > psg_len(raw))) || (raw.bytesize > 8192)) || raw.include?("\u{0}"))
    return :psg_null
  end
  tokens = []
  groups = []
  kv = {}
  pos = start
  count = 0
  while (pos < psg_len(raw))
    while ((pos < psg_len(raw)) && /[ \t\n\r\f\x0b]/.match?(psg_at(raw, pos)))
      pos += 1
    end
    if (pos == psg_len(raw))
      break
    end
    if ((count += 1) > 100)
      return :psg_null
    end
    if ((psg_at(raw, pos) == '"') || (psg_at(raw, pos) == '\''))
      quote = psg_at(raw, pos)
      v_begin = (pos + 1)
      cursor = v_begin
      closed = false
      while (cursor < psg_len(raw))
        if ((psg_at(raw, cursor) == '\\') && ((cursor + 1) < psg_len(raw)))
          cursor += 2
          next
        end
        if (psg_at(raw, cursor) == quote)
          closed = true
          break
        end
        cursor += 1
      end
      if !closed
        return :psg_null
      end
      tokens.push(psg_slice(raw, v_begin, cursor))
      cursor += 1
      if ((cursor < psg_len(raw)) && '.,:!?'.include?(psg_at(raw, cursor)))
        cursor += 1
      end
      if (((cursor < psg_len(raw)) && !/[ \t\n\r\f\x0b]/.match?(psg_at(raw, cursor))) && ![';', ','].include?(psg_at(raw, cursor)))
        return :psg_null
      end
      pos = cursor
      if ((pos < psg_len(raw)) && [';', ','].include?(psg_at(raw, pos)))
        pos += 1
      end
      next
    end
    if (psg_at(raw, pos) == '(')
      v_end = psg_index(raw, ')', (pos + 1))
      if ((v_end < 0) || (((v_end + 1) < psg_len(raw)) && !/[ \t\n\r\f\x0b]/.match?(psg_at(raw, (v_end + 1)))))
        return :psg_null
      end
      groups.push(psg_slice(raw, (pos + 1), v_end))
      pos = (v_end + 1)
      next
    end
    keyMatch = (/\A([A-Za-z_][A-Za-z0-9_.\-]{0,127})=/.match(psg_slice(raw, pos)) || :psg_null)
    if psg_t(keyMatch)
      key = keyMatch[1]
      if !psg_source_key_safe(key)
        return :psg_null
      end
      cursor_2 = (pos + psg_len(keyMatch[0]))
      startValue = cursor_2
      v_end_2 = cursor_2
      quote_2 = psg_at(raw, cursor_2)
      if ((quote_2 == '"') || (quote_2 == '\''))
        startValue = (cursor_2 += 1)
        closed_2 = false
        while (cursor_2 < psg_len(raw))
          if ((psg_at(raw, cursor_2) == '\\') && ((cursor_2 + 1) < psg_len(raw)))
            cursor_2 += 2
            next
          end
          if (psg_at(raw, cursor_2) == quote_2)
            v_end_2 = cursor_2
            cursor_2 += 1
            closed_2 = true
            break
          end
          cursor_2 += 1
        end
        if (!closed_2 || ((cursor_2 < psg_len(raw)) && !/[ \t\n\r\f\x0b]/.match?(psg_at(raw, cursor_2))))
          return :psg_null
        end
      else
        while ((cursor_2 < psg_len(raw)) && !/[ \t\n\r\f\x0b]/.match?(psg_at(raw, cursor_2)))
          cursor_2 += 1
        end
        v_end_2 = cursor_2
      end
      value = psg_slice(raw, startValue, v_end_2)
      previous = kv[key]
      kv[key] = (previous.nil? ? value : (previous.is_a?(Array) ? [*previous, value] : [previous, value]))
      pos = cursor_2
      next
    end
    v_begin_2 = pos
    while ((pos < psg_len(raw)) && !/[ \t\n\r\f\x0b]/.match?(psg_at(raw, pos)))
      pos += 1
    end
    tokens.push(psg_slice(raw, v_begin_2, pos))
  end
  return {'tokens' => tokens, 'kv' => kv, 'groups' => groups}
end

# src/genericStructural.ts: securityPositionalCsvBody
def psg_security_positional_csv_body(text)
  values = ip = validIp = columns = nil
  values = psg_positional_csv_values(text)
  if ((!psg_t(values) || (values.length < 12)) || (values.length > 150))
    return :psg_null
  end
  ip = /\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/
  validIp = lambda { |value| (ip.match?(value) && psg_every(psg_split(value, '.'), lambda { |part| (psg_num(part) <= 255) })) }
  if (psg_filter(values, validIp).length < 2)
    return :psg_null
  end
  columns = {}
  psg_for_each(values, lambda { |value_2, index|
  columns[('column_' + psg_str(index))] = value_2
  nil
})
  return columns
end

# src/genericStructural.ts: shortRfc5424Json
def psg_short_rfc5424_json(raw)
  match = pri = body = nil
  match = (/\A<([0-9]{1,3})>(1) ([^ \t\n\r\f\x0b]{1,64}) ([!-~]{1,255}) (\{(?m:.)*\})\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  pri = psg_num(match[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !psg_valid_rfc3339(match[3]))
    return :psg_null
  end
  body = psg_parse_json_body(match[5])
  if ((!psg_t(body) || body.is_a?(Array)) || !(psg_typeof(body) == 'object'))
    return :psg_null
  end
  return psg_with_body_text({'syslog' => {'pri' => match[1], 'version' => match[2], 'timestamp' => match[3], 'hostname' => match[4]}, 'body' => body}, 'json', match[5])
end

# src/genericStructural.ts: shortRfc5424Structured
def psg_short_rfc5424_structured(raw)
  match = pri = source = parsed = nil
  match = (/\A<([0-9]{1,3})>(1) ([^ \t\n\r\f\x0b]{1,64}) ([!-~]{1,255}) ((?:CEF: ?0\|(?m:.)*|LEEF:(?:1\.0|2\.0)\|(?m:.)*))\z/.match(raw) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  pri = psg_num(match[1])
  if (((!psg_integer?(pri) || (pri < 0)) || (pri > 191)) || !psg_valid_rfc3339(match[3]))
    return :psg_null
  end
  source = match[5]
  parsed = psg_extract_structured_family(source, (source.start_with?('CEF:') ? 'cef' : 'leef'))
  if psg_t(parsed['errors'].length)
    return :psg_null
  end
  return {'syslog' => {'pri' => match[1], 'version' => match[2], 'timestamp' => match[3], 'hostname' => match[4]}, 'body' => parsed['fields']}
end

# src/genericStructural.ts: sourceKeySafe
def psg_source_key_safe(key)
  return !psg_k_unsafe_source_keys.key?(key)
end

# src/genericStructural.ts: spaceKv
def psg_space_kv(raw)
  entries = prefix = tokens = fields = atoms = index = entry = v_end = value = quoted = pieces = pieceIndex = piece = safe = generic = nil
  if (raw.bytesize > 8192)
    return :psg_null
  end
  entries = psg_space_kv_entries(raw)
  if !psg_t(entries)
    return :psg_null
  end
  if (entries.length < 5)
    return :psg_null
  end
  prefix = psg_replace(psg_slice(raw, 0, entries[0]['start']), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
  tokens = (psg_t(prefix) ? psg_map(psg_split(prefix, /[ \t]+/), lambda { |value_2| (((psg_len(value_2) > 1) && [':', ','].include?(psg_at(value_2, (psg_len(value_2) - 1)))) ? psg_slice(value_2, 0, (-1)) : value_2) }) : [])
  if (psg_t(prefix) && (((tokens.length < 2) || (tokens.length > 16)) || psg_some(tokens, lambda { |value_3| (!psg_t(value_3) || (value_3.bytesize > 256)) })))
    return :psg_null
  end
  fields = {}
  atoms = {}
  index = 0
  while (index < entries.length)
    entry = psg_at(entries, index)
    if (!psg_source_key_safe(entry['key']) || fields.key?(entry['key']))
      return :psg_null
    end
    v_end = (((index + 1) < entries.length) ? psg_at(entries, (index + 1))['start'] : psg_len(raw))
    value = psg_replace(psg_slice(raw, entry['valueStart'], v_end), /\A[ \t\n\x0b\f\r]+|[ \t\n\x0b\f\r]+\z/, true, '')
    quoted = ((psg_len(value) >= 2) && ((value.start_with?('"') && value.end_with?('"')) || (value.start_with?('\'') && value.end_with?('\''))))
    if quoted
      value = psg_slice(value, 1, (-1))
    elsif (((value.start_with?('"') || value.start_with?('\'')) || value.end_with?('"')) || value.end_with?('\''))
      return :psg_null
    end
    if (/[\x00-\x1f\x7f]/.match?(value) || (value.bytesize > 512))
      return :psg_null
    end
    fields[entry['key']] = value
    if (!quoted && /[ \t]/.match?(value))
      pieces = psg_filter(psg_split(value, /[ \t]+/), lambda { |piece_2| (piece_2 != '') })
      if (pieces.length > 32)
        return :psg_null
      end
      pieceIndex = 0
      while (pieceIndex < pieces.length)
        piece = psg_at(pieces, pieceIndex)
        if (piece.bytesize > 256)
          return :psg_null
        end
        safe = ((psg_replace(entry['key'], '-', true, '_') + '_') + psg_pad_start(psg_str((pieceIndex + 1)), 3, '0'))
        if atoms.key?(safe)
          return :psg_null
        end
        atoms[safe] = piece
        if (atoms.keys.length > 100)
          return :psg_null
        end
        pieceIndex += 1
      end
    end
    index += 1
  end
  generic = {'mode' => 'space_kv', 'source_raw' => raw, 'kv' => fields}
  psg_for_each(tokens, lambda { |value_4, index_2|
  generic[('prefix_' + psg_pad_start(psg_str((index_2 + 1)), 3, '0'))] = value_4
  nil
})
  if psg_t(atoms.keys.length)
    generic['atoms'] = atoms
  end
  return {'generic' => generic}
end

# src/genericStructural.ts: spaceKvEntries
def psg_space_kv_entries(raw)
  entries = quote = escaped = pos = char = boundary = match = nil
  entries = []
  quote = ''
  escaped = false
  pos = 0
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else pos += 1 end
    break unless (pos < psg_len(raw))
    char = psg_at(raw, pos)
    if psg_t(quote)
      if escaped
        escaped = false
        next
      end
      if (char == '\\')
        escaped = true
        next
      end
      if (char == quote)
        quote = ''
      end
      next
    end
    boundary = (((pos == 0) || (psg_at(raw, (pos - 1)) == ' ')) || (psg_at(raw, (pos - 1)) == "\u{9}"))
    if boundary
      match = (/\A([A-Za-z_][A-Za-z0-9_.\-]{0,63})=/.match(psg_slice(raw, pos)) || :psg_null)
      if psg_t(match)
        entries.push({'key' => match[1], 'start' => pos, 'valueStart' => (pos + psg_len(match[0]))})
        if (entries.length > 100)
          return :psg_null
        end
      end
    end
    if ((char == '"') || (char == '\''))
      quote = char
    end
  end
  return ((psg_t(quote) || escaped) ? :psg_null : entries)
end

# src/genericStructural.ts: splitEscaped
def psg_split_escaped_2(value, delimiter)
  parts = token = quote = escaped = nil
  parts = []
  token = ''
  quote = ''
  escaped = false
  value.each_char do |char|
    if escaped
      token += char
      escaped = false
      next
    end
    if (char == '\\')
      token += char
      escaped = true
      next
    end
    if psg_t(quote)
      token += char
      if (char == quote)
        quote = ''
      end
      next
    end
    if ((char == '"') || (char == '\''))
      quote = char
      token += char
      next
    end
    if (char == delimiter)
      parts.push(token)
      token = ''
      next
    end
    token += char
  end
  if (escaped || psg_t(quote))
    return :psg_null
  end
  parts.push(token)
  return parts
end

# src/syslogEnvelope.ts: splitPri
def psg_split_pri(raw)
  match = decoded = nil
  match = (/\A<([0-9]{1,3})>/.match(raw) || :psg_null)
  if !psg_t(match)
    return {'rest' => raw}
  end
  decoded = psg_decompose_pri(match[1])
  if !psg_t(decoded)
    return :psg_null
  end
  return {'pri' => match[1], 'rest' => psg_slice(raw, psg_len(match[0]))}
end

# src/genericStructural.ts: structuredFamilyClaim
def psg_structured_family_claim(raw)
  match = nil
  match = psg_match_at(/\G(?:(?<family>(?:CEF|LEEF))(?:(?:[ \t]))*:(?:(?:[ \t]))*(?:[0-9]))/, raw, 0)
  return (psg_t(match) ? psg_group(match, 'family') : :psg_null)
end

# src/genericStructural.ts: syslogEnvelopeStructuredFallback
def psg_syslog_envelope_structured_fallback(raw)
  envelope = syslog = message = parsed = vendorSyslog = juniper = bracket = watchguard = parsed_2 = parsed_3 = json = panosValues = panosLike = panos = named = namedMode = positional = comma = spaced = nil
  envelope = psg_parse_syslog_envelope(raw)
  if (!psg_t(envelope) || (envelope['variant'] == 'colon_date'))
    return :psg_null
  end
  syslog = psg_envelope_to_syslog_fields(envelope)
  message = envelope['message']
  if /\A%(?:ASA|FTD)-/.match?(message)
    parsed = psg_asa(message)
    if (!psg_t((psg_null?(psg_t1 = parsed) ? nil : psg_t1['asa'])) || !(psg_typeof(parsed['asa']) == 'object'))
      return :psg_null
    end
    vendorSyslog = ((psg_t(parsed['syslog']) && (psg_typeof(parsed['syslog']) == 'object')) ? parsed['syslog'] : {})
    return {'syslog' => {}.merge!(syslog).merge!(vendorSyslog), 'asa' => {}.merge!(parsed['asa']).merge!({'source_raw' => raw, 'message_raw' => message})}
  end
  if (envelope['appname'] == 'RT_FLOW')
    juniper = psg_juniper_rt_flow_body(message)
    if psg_t(juniper)
      return {'syslog' => syslog, 'juniper' => {}.merge!(juniper).merge!({'source_raw' => raw, 'message_raw' => message})}
    end
    return :psg_null
  end
  if message.start_with?('[')
    bracket = psg_bracket_colon_kv_body(message)
    if psg_t(bracket)
      return {'syslog' => syslog, 'body' => bracket, 'generic' => {'mode' => 'syslog_envelope_bracket_colon_kv', 'source_raw' => raw, 'message_raw' => message}}
    end
    return :psg_null
  end
  watchguard = psg_watchguard_traffic_body(message)
  if psg_t(watchguard)
    return {'syslog' => syslog, 'watchguard_header' => watchguard['header'], 'watchguard' => {}.merge!(watchguard['body']).merge!({'source_raw' => raw, 'message_raw' => message})}
  end
  if /(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))firewall(?:\[[0-9]{1,8}\])?: +msg_id=/.match?(message)
    return :psg_null
  end
  if message.start_with?('CEF:')
    if !/\ACEF: ?0\|/.match?(message)
      return :psg_null
    end
    parsed_2 = psg_extract_structured_family(message, 'cef')
    if psg_t(parsed_2['errors'].length)
      return :psg_null
    end
    return psg_with_body_text({'syslog' => syslog, 'body' => parsed_2['fields'], 'generic' => {'mode' => 'syslog_envelope_cef', 'source_raw' => raw, 'message_raw' => message}}, 'cef', message)
  end
  if message.start_with?('LEEF:')
    if !/\ALEEF:(?:1\.0|2\.0)\|/.match?(message)
      return :psg_null
    end
    parsed_3 = psg_extract_structured_family(message, 'leef')
    if psg_t(parsed_3['errors'].length)
      return :psg_null
    end
    return psg_with_body_text({'syslog' => syslog, 'body' => parsed_3['fields'], 'generic' => {'mode' => 'syslog_envelope_leef', 'source_raw' => raw, 'message_raw' => message}}, 'leef', message)
  end
  if message.start_with?('{')
    json = psg_bounded_envelope_json(message)
    if !psg_t(json)
      return :psg_null
    end
    return psg_with_body_text({'syslog' => syslog, 'body' => json, 'generic' => {'mode' => 'syslog_envelope_json', 'source_raw' => raw, 'message_raw' => message}}, 'json', message)
  end
  panosValues = psg_positional_csv_values(message)
  panosLike = (((((!!psg_t(panosValues) && (panosValues.length >= 7)) && /\A[0-9]{0,10}\z/.match?((psg_null?(psg_t2 = panosValues[0]) ? '' : psg_t2))) && /\A[0-9]{4}\/[0-9]{2}\/[0-9]{2} +[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?\z/.match?((psg_null?(psg_t3 = panosValues[1]) ? '' : psg_t3))) && /\A[A-Za-z0-9_.:\-]{4,64}\z/.match?((psg_null?(psg_t4 = panosValues[2]) ? '' : psg_t4))) && /\A[A-Z][A-Z0-9_]{2,31}\z/.match?((psg_null?(psg_t5 = panosValues[3]) ? '' : psg_t5)))
  panos = psg_panos_positional_csv_body(message)
  if psg_t(panos)
    named = (psg_t(panosValues) ? psg_panos_named_fields(panosValues) : :psg_null)
    namedMode = (psg_t(panosValues) ? psg_panos_named_mode(panosValues) : :psg_null)
    return psg_with_body_text({'syslog' => syslog, 'generic' => (psg_t(named) ? {'mode' => namedMode, 'profile' => 'panos', 'delimiter' => ',', 'source_raw' => raw, 'message_raw' => message, 'fields' => named} : {'mode' => 'syslog_envelope_positional_csv', 'profile' => 'panos', 'delimiter' => ',', 'source_raw' => raw, 'message_raw' => message, 'columns' => panos})}, 'positional_csv', message)
  end
  if panosLike
    return :psg_null
  end
  positional = psg_security_positional_csv_body(message)
  if psg_t(positional)
    return psg_with_body_text({'syslog' => syslog, 'generic' => {'mode' => 'syslog_envelope_positional_csv', 'delimiter' => ',', 'source_raw' => raw, 'message_raw' => message, 'columns' => positional}}, 'positional_csv', message)
  end
  comma = psg_delimited_comma_kv(message)
  if (psg_t((psg_null?(psg_t6 = comma) ? nil : psg_t6['generic'])) && (psg_typeof(comma['generic']) == 'object'))
    return {'syslog' => syslog, 'generic' => {}.merge!(comma['generic']).merge!({'source_raw' => raw, 'message_raw' => message})}
  end
  spaced = psg_space_kv(message)
  if (psg_t((psg_null?(psg_t7 = spaced) ? nil : psg_t7['generic'])) && (psg_typeof(spaced['generic']) == 'object'))
    return {'syslog' => syslog, 'generic' => {}.merge!(spaced['generic']).merge!({'source_raw' => raw, 'message_raw' => message})}
  end
  return :psg_null
end

# src/genericStructural.ts: syslogPrefixedKeyValues
def psg_syslog_prefixed_key_values(raw)
  head = message = first = cursor = prefix = fields = token = match = key = value = nil
  if ((raw.bytesize > 8192) || /[\x00-\x08\x0a-\x1f\x7f]/.match?(raw))
    return :psg_null
  end
  head = (/\A<([0-9]{1,3})>([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}:[0-9]{2}:[0-9]{2}) +([!-~]{1,255}) +([^\r\n]+)\z/.match(raw) || :psg_null)
  if ((!psg_t(head) || (psg_num(head[1]) > 191)) || !psg_valid_bsd_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  message = head[6]
  first = (/[ \t]([A-Za-z_][A-Za-z0-9_\-]{0,63})=/.match(message) || :psg_null)
  if !psg_t(first)
    return :psg_null
  end
  cursor = (psg_match_index(first) + 1)
  prefix = psg_slice(message, 0, cursor)
  if (((!/[^ \t\u{85}\u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}]/.match?(prefix) || (prefix.bytesize > 1024)) || /[="'{}\[\]|<>\/]/.match?(prefix)) || /(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9A-Fa-f]{0,4}:){2}|->/.match?(prefix))
    return :psg_null
  end
  fields = {}
  token = /\A([A-Za-z_][A-Za-z0-9_\-]{0,63})=(?:"((?:\\["\\]|[^"\\\x00-\x1f\x7f])*)"|'((?:\\['\\]|[^'\\\x00-\x1f\x7f])*)'|([^ \t"'\\]+))(?=[ \t]|\z)/
  while (cursor < psg_len(message))
    match = (token.match(psg_slice(message, cursor)) || :psg_null)
    if !psg_t(match)
      return :psg_null
    end
    key = match[1]
    value = (psg_null?(psg_t1 = (psg_null?(psg_t2 = match[2]) ? match[3] : psg_t2)) ? match[4] : psg_t1)
    if ((!psg_source_key_safe(key) || fields.key?(key)) || (value.bytesize > 512))
      return :psg_null
    end
    fields[key] = value
    if (fields.keys.length > 60)
      return :psg_null
    end
    cursor += psg_len(match[0])
    while ((cursor < psg_len(message)) && /[ \t]/.match?(psg_at(message, cursor)))
      cursor += 1
    end
  end
  if (fields.keys.length < 2)
    return :psg_null
  end
  return {'syslog' => {'pri' => head[1], 'month' => head[2], 'day' => head[3], 'time' => head[4], 'hostname' => head[5], 'time_policy' => 'YEAR_AND_ZONE_UNKNOWN'}, 'generic' => {'mode' => 'syslog_prefix_kv', 'prefix' => prefix, 'message_raw' => message, 'source_raw' => raw, 'kv' => fields}}
end

# src/grammar/syslogHeader.ts: unsupportedRfc5424Version
def psg_unsupported_rfc5424_version(text)
  match = version = nil
  match = psg_match_at(/\G(?:<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?:-[ ]|(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T)))/, text, 0)
  if !psg_t(match)
    return :psg_null
  end
  version = psg_group(match, 'version')
  return (psg_is_supported_rfc5424_version(version) ? :psg_null : version)
end

# src/syslogEnvelope.ts: utf8Size
def psg_utf8_size(value)
  return value.bytesize
end

# src/genericStructural.ts: validBsdClock
def psg_valid_bsd_clock(month, dayText, time)
  monthDays = day = clock = nil
  monthDays = {'Jan' => 31, 'Feb' => 29, 'Mar' => 31, 'Apr' => 30, 'May' => 31, 'Jun' => 30, 'Jul' => 31, 'Aug' => 31, 'Sep' => 30, 'Oct' => 31, 'Nov' => 30, 'Dec' => 31}
  day = psg_num(dayText)
  clock = psg_map(psg_split(time, ':'), lambda { |part| psg_num(part) })
  return ((((((((((!!psg_t(monthDays[month]) && psg_integer?(day)) && (day >= 1)) && (day <= monthDays[month])) && (clock.length == 3)) && (clock[0] >= 0)) && (clock[0] <= 23)) && (clock[1] >= 0)) && (clock[1] <= 59)) && (clock[2] >= 0)) && (clock[2] <= 59))
end

# src/syslogEnvelope.ts: validBsdTimestamp
def psg_valid_bsd_timestamp(month, dayText, time)
  day = nil
  day = psg_num(dayText)
  return ((((!!psg_t(psg_k_month_days[month]) && psg_integer?(day)) && (day >= 1)) && (day <= psg_k_month_days[month])) && psg_valid_clock(time))
end

# src/syslogEnvelope.ts: validCalendarDate
def psg_valid_calendar_date(year, month, day)
  days = nil
  if (((((((!psg_integer?(year) || (year < 1)) || (year > 9999)) || !psg_integer?(month)) || (month < 1)) || (month > 12)) || !psg_integer?(day)) || (day < 1))
    return false
  end
  days = [31, (psg_leap_year(year) ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return (day <= psg_at(days, (month - 1)))
end

# src/syslogEnvelope.ts: validClock
def psg_valid_clock(value)
  match = nil
  match = (/\A([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?\z/.match(value) || :psg_null)
  if !psg_t(match)
    return false
  end
  return (((psg_num(match[1]) <= 23) && (psg_num(match[2]) <= 59)) && (psg_num(match[3]) <= 59))
end

# src/genericStructural.ts: validIsoPriClock
def psg_valid_iso_pri_clock(date, time, timezone)
  d = t = year = month = day = hour = minute = second = leap = days = zone = nil
  d = (/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/.match(date) || :psg_null)
  t = (/\A([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?\z/.match(time) || :psg_null)
  if (!psg_t(d) || !psg_t(t))
    return false
  end
  year = psg_num(d[1])
  month = psg_num(d[2])
  day = psg_num(d[3])
  hour = psg_num(t[1])
  minute = psg_num(t[2])
  second = psg_num(t[3])
  if (((((((year < 1) || (year > 9999)) || (month < 1)) || (month > 12)) || (hour > 23)) || (minute > 59)) || (second > 59))
    return false
  end
  leap = ((psg_mod(year, 4) == 0) && ((psg_mod(year, 100) != 0) || (psg_mod(year, 400) == 0)))
  days = [31, (leap ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if ((day < 1) || (day > psg_at(days, (month - 1))))
    return false
  end
  if (timezone == 'Z')
    return true
  end
  zone = (/\A([+\-])([0-9]{2}):?([0-9]{2})\z/.match(timezone) || :psg_null)
  return ((!!psg_t(zone) && (psg_num(zone[2]) <= 23)) && (psg_num(zone[3]) <= 59))
end

# src/syslogEnvelope.ts: validIsoTimestamp
def psg_valid_iso_timestamp(value, requireZone)
  match = nil
  match = (/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?)(Z|[+\-][0-9]{2}:?[0-9]{2})?\z/.match(value) || :psg_null)
  if !psg_t(match)
    return false
  end
  if (requireZone && !psg_t(match[5]))
    return false
  end
  return ((psg_valid_calendar_date(psg_num(match[1]), psg_num(match[2]), psg_num(match[3])) && psg_valid_clock(match[4])) && (!psg_t(match[5]) || psg_valid_zone(match[5])))
end

# src/genericStructural.ts: validRfc3339
def psg_valid_rfc3339(value)
  return (/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+\-][0-9]{2}:[0-9]{2})\z/.match?(value) && psg_iso_timestamp_ok(value))
end

# src/genericStructural.ts: validUnzonedTimestamp
def psg_valid_unzoned_timestamp(value)
  return (/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\z/.match?(value) && psg_iso_timestamp_ok(value))
end

# src/syslogEnvelope.ts: validZone
def psg_valid_zone(value)
  match = nil
  if (value == 'Z')
    return true
  end
  match = (/\A([+\-])([0-9]{2}):?([0-9]{2})\z/.match(value) || :psg_null)
  return ((!!psg_t(match) && (psg_num(match[2]) <= 23)) && (psg_num(match[3]) <= 59))
end

# src/genericStructural.ts: watchguardMessageProfile
def psg_watchguard_message_profile(raw)
  head = header = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  head = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255})(?: +([A-Za-z0-9.\-]{2,64}))? +\(([0-9T:+\-]{19,35})\) +(firewall(?:\[[0-9]{1,8}\])?): +msg_id="([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})" +((?m:.)+)\z/.match(raw) || :psg_null)
  if (!psg_t(head) || !psg_valid_bsd_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  if (!head[1].nil? && ((psg_num(head[1]) < 0) || (psg_num(head[1]) > 191)))
    return :psg_null
  end
  if !psg_iso_timestamp_ok(head[7])
    return :psg_null
  end
  header = {'month' => head[2], 'day' => head[3], 'time' => head[4], 'hostname' => head[5], 'device_time' => head[7], 'app_tag' => head[8]}
  if !head[1].nil?
    header['pri'] = head[1]
  end
  if !head[6].nil?
    header['serial'] = head[6]
  end
  return {'watchguard_header' => header, 'watchguard_message' => {'source_raw' => raw, 'msg_id' => head[9], 'message' => head[10]}}
end

# src/genericStructural.ts: watchguardProfile
def psg_watchguard_profile(raw)
  head = body = msgId = header = nil
  head = (/\A(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) +([^ \t\n\r\f\x0b]{1,255})(?: +([A-Za-z0-9.\-]{2,64}))?(?: +\(([0-9T:+\-]{19,35})\))? +(firewall(?:\[[0-9]{1,8}\])?): +/.match(raw) || :psg_null)
  if (!psg_t(head) || !psg_valid_bsd_clock(head[2], head[3], head[4]))
    return :psg_null
  end
  if (!head[1].nil? && ((psg_num(head[1]) < 0) || (psg_num(head[1]) > 191)))
    return :psg_null
  end
  if (!head[7].nil? && !psg_iso_timestamp_ok(head[7]))
    return :psg_null
  end
  body = psg_scan_profile_tokens(raw, psg_len(head[0]))
  if ((!psg_t(body) || !psg_t(body['tokens'].length)) || !['Allow', 'Deny', 'Drop'].include?(body['tokens'][0]))
    return :psg_null
  end
  msgId = body['kv']['msg_id']
  if (!msgId.is_a?(String) || !/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/.match?(msgId))
    return :psg_null
  end
  if (psg_filter(body['tokens'], method(:psg_ip_token)).length < 2)
    return :psg_null
  end
  header = {'month' => head[2], 'day' => head[3], 'time' => head[4], 'hostname' => head[5], 'app_tag' => head[8]}
  if !head[1].nil?
    header['pri'] = head[1]
  end
  if !head[6].nil?
    header['serial'] = head[6]
  end
  if !head[7].nil?
    header['device_time'] = head[7]
  end
  return {'watchguard_header' => header, 'watchguard' => body}
end

# src/genericStructural.ts: watchguardTrafficBody
def psg_watchguard_traffic_body(text)
  head = body = msgId = nil
  head = (/\A(?:([A-Za-z0-9.\-]{2,64}) +)?(?:\(([0-9T:+\-]{19,35})\) +)?(firewall(?:\[[0-9]{1,8}\])?): +/.match(text) || :psg_null)
  if !psg_t(head)
    return :psg_null
  end
  if (!head[2].nil? && !psg_iso_timestamp_ok(head[2]))
    return :psg_null
  end
  body = psg_scan_profile_tokens(text, psg_len(head[0]))
  if ((!psg_t(body) || !psg_t(body['tokens'].length)) || !['Allow', 'Deny', 'Drop'].include?(body['tokens'][0]))
    return :psg_null
  end
  msgId = body['kv']['msg_id']
  if (!msgId.is_a?(String) || !/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/.match?(msgId))
    return :psg_null
  end
  if (psg_filter(body['tokens'], method(:psg_ip_token)).length < 2)
    return :psg_null
  end
  return {'header' => {}.merge!((psg_t(head[1]) ? {'serial' => head[1]} : {})).merge!((psg_t(head[2]) ? {'device_time' => head[2]} : {})).merge!({'app_tag' => head[3]}), 'body' => body}
end

# src/genericStructural.ts: watchguardTrafficMonitorProfile
def psg_watchguard_traffic_monitor_profile(raw)
  head = details = msgId = record = header = nil
  if ((raw.bytesize > 8192) || raw.include?("\u{0}"))
    return :psg_null
  end
  head = (/\A([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) (?:([A-Za-z0-9._\-]{1,64}) )?(Allow|Deny|Drop) ([0-9A-Fa-f:.]{2,45}) ([0-9A-Fa-f:.]{2,45}) ([A-Za-z0-9._\-]{1,64})\/([A-Za-z0-9\-]{1,16}) (?:([0-9]{1,5}) ([0-9]{1,5}) )?([A-Za-z0-9._\-]{1,64}) ([A-Za-z0-9._\-]{1,64}) ([A-Za-z]{1,32}) (?:([0-9]{1,5}) ([0-9]{1,3}) )?\(([^()]{1,128})\) /.match(raw) || :psg_null)
  if (((!psg_t(head) || !psg_iso_timestamp_ok(((head[1] + 'T') + head[2]))) || !psg_ip_token(head[5])) || !psg_ip_token(head[6]))
    return :psg_null
  end
  if (!head[9].nil? && ((psg_num(head[9]) > 65535) || (psg_num(head[10]) > 65535)))
    return :psg_null
  end
  if (!head[9].nil? && !/\A(?:[Tt][Cc][Pp]|[Uu][Dd][Pp])\z/.match?(head[8]))
    return :psg_null
  end
  if (!head[15].nil? && (psg_num(head[15]) > 255))
    return :psg_null
  end
  details = psg_scan_profile_tokens(raw, psg_len(head[0]))
  if ((!psg_t(details) || (details['tokens'].length > 0)) || (details['groups'].length > 0))
    return :psg_null
  end
  msgId = details['kv']['msg_id']
  if (!msgId.is_a?(String) || !/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/.match?(msgId))
    return :psg_null
  end
  record = {'disp' => head[4], 'src_ip' => head[5], 'dst_ip' => head[6], 'service' => head[7], 'protocol' => head[8]}
  if !head[9].nil?
    record['src_port'] = head[9]
    record['dst_port'] = head[10]
  end
  record['src_intf'] = head[11]
  record['dst_intf'] = head[12]
  record['connection_action'] = head[13]
  if !head[14].nil?
    record['pckt_len'] = head[14]
    record['ttl'] = head[15]
  end
  record['policy'] = head[16]
  record['kv'] = details['kv']
  header = {'date' => head[1], 'time' => head[2]}
  if !head[3].nil?
    header['cluster'] = head[3]
  end
  return {'watchguard_header' => header, 'watchguard' => record, 'generic' => {'mode' => 'watchguard_traffic_monitor', 'source_raw' => raw}}
end

# src/genericStructural.ts: withBodyText
def psg_with_body_text(fields, kind, text)
  psg_set_tag(fields, 'bodyKind', kind)
  psg_set_tag(fields, 'bodyText', text)
  return fields
end

# src/syslogEnvelope.ts: withPri
def psg_with_pri(pri = nil)
  return (psg_null?(psg_t1 = psg_decompose_pri(pri)) ? {} : psg_t1)
end

# src/grammar/genericParseStatus.ts: withoutBackslashes
def psg_without_backslashes(text)
  psg_join(psg_split(text, '\\'), '')
end
