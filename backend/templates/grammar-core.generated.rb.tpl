# GENERATED FILE - DO NOT EDIT.
# Parser Studio grammar: every format of the generated parser, generated from the grammar the browser executes.
# Source: src/grammar/readEvent.ts (readEvent), src/grammar/extractEvent.ts (extractEvent), src/grammar/extractEvent.ts (tokenizeCsvRow) and the functions they reach.
# Regenerate with: node scripts/grammar/ts2rb/generate.mjs --write
# CI runs the generator with --verify, so a hand edit of this file fails the gate.

# src/grammar/lossGuard.ts: CEF_ESCAPES
def psg_k_cef_escapes
  @psg_k_cef_escapes ||= {'n' => "\u{a}", 'r' => "\u{d}", '=' => '=', '\\' => '\\'}
end

# src/structuredFamilies.ts: CEF_ESCAPES
def psg_k_cef_escapes_2
  @psg_k_cef_escapes_2 ||= {'n' => "\u{a}", 'r' => "\u{d}", '=' => '=', '\\' => '\\'}
end

# src/grammar/lossGuard.ts: CEF_HEADER_FIELDS
def psg_k_cef_header_fields
  @psg_k_cef_header_fields ||= ['cef_version', 'cef_device_vendor', 'cef_device_product', 'cef_device_version', 'cef_signature_id', 'cef_name', 'cef_severity']
end

# src/structuredFamilies.ts: CEF_VERSIONS
def psg_k_cef_versions
  @psg_k_cef_versions ||= ['0']
end

# src/grammar/syslogHeader.ts: COMPILED_RULES
def psg_k_compiled_rules
  @psg_k_compiled_rules ||= {'rfc3164_tagged' => /\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?!(?:(?:CEF|LEEF))(?:(?:[ \t]))*:(?:(?:[ \t]))*(?:[0-9]))(?<tag>[A-Za-z_][A-Za-z0-9_.\-]{0,95})(?:\[(?<procid>[0-9]{1,8})\])?:[ ]+(?<message>[^\r\n]+)\z/, 'rfc3164_tagless' => /\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<message>[^\r\n]+)\z/, 'rfc3164_hostless' => /\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.\-]{0,95}=)[^\r\n]*)\z/, 'rfc5424' => /\A<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?<timestamp>[!-~]{1,64})[ ](?<hostname>[!-~]{1,255})[ ](?<appname>[!-~]{1,48})[ ](?<procid>[!-~]{1,128})[ ](?<msgid>[!-~]{1,32})[ ](?<rest>[^\r\n]+)\z/}
end

# src/grammar/syslogHeader.ts: COMPILED_TOKENS
def psg_k_compiled_tokens
  @psg_k_compiled_tokens ||= {'PRI' => /\A(?:[0-9]{1,3})\z/, 'BSD_MONTH' => /\A(?:[A-Z][a-z]{2})\z/, 'BSD_DAY' => /\A(?:[0-9]{1,2})\z/, 'CLOCK2' => /\A(?:[0-9]{2})\z/, 'BSD_HOSTNAME' => /\A(?:(?!\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])\z/, 'TAG' => /\A(?:[A-Za-z_][A-Za-z0-9_.\-]{0,95})\z/, 'PROCID_NUM' => /\A(?:[0-9]{1,8})\z/, 'REST' => /\A(?:[^\r\n]+)\z/, 'STRUCTURED_BODY' => /\A(?:(?:\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.\-]{0,95}=)[^\r\n]*)\z/, 'RFC5424_VERSION' => /\A(?:[1-9][0-9]{0,2})\z/, 'RFC5424_TIMESTAMP' => /\A(?:[!-~]{1,64})\z/, 'RFC5424_HOSTNAME' => /\A(?:[!-~]{1,255})\z/, 'RFC5424_APPNAME' => /\A(?:[!-~]{1,48})\z/, 'RFC5424_PROCID' => /\A(?:[!-~]{1,128})\z/, 'RFC5424_MSGID' => /\A(?:[!-~]{1,32})\z/, 'KV_GAP' => /\A(?:[ \t]*)\z/, 'KV_KEY' => /\A(?:[A-Za-z_][A-Za-z0-9_.\-]{0,95})\z/, 'KV_DQ' => /\A(?:(?:\\[^\r\n]|[^"\\])*)\z/, 'KV_SQ' => /\A(?:(?:\\[^\r\n]|[^'\\])*)\z/, 'KV_BARE' => /\A(?:(?:\\[^ \t\n\r\f\x0b\x1c-\x1f]|[^ \t\n\r\f\x0b\x1c-\x1f"'\\]|\\)+)\z/, 'KV_LIST_BARE' => /\A(?:[^ \t\n\r\f\x0b\x1c-\x1f"',;|=]+)\z/, 'KV_LIST_DQ' => /\A(?:[^"]*)\z/, 'KV_LIST_SQ' => /\A(?:[^']*)\z/, 'KV_LIST_DELIMITER' => /\A(?:[,;|])\z/, 'KV_TRAILING' => /\A(?:[ \t\n\r\f\x0b]*)\z/, 'RFC3339_DATE_PREFIX' => /\A(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T)\z/, 'FAMILY_NAME' => /\A(?:(?:CEF|LEEF))\z/, 'ASCII_DIGIT' => /\A(?:[0-9])\z/, 'CEF_KEY' => /\A(?:[A-Za-z_][A-Za-z0-9_.\-]{0,127})\z/, 'LEEF_KEY' => /\A(?:[A-Za-z_][A-Za-z0-9_.\-]*)\z/, 'CEF_WS' => /\A(?:[ \t])\z/, 'CEF_WS_RUN' => /\A(?:[ \t]+)\z/, 'CEF_NOT_WS' => /\A(?:[^ \t])\z/, 'CEF_ESCAPE' => /\A(?:\\[^ \t])\z/, 'CEF_PLAIN' => /\A(?:[^\\ \t])\z/, 'CEF_BACKSLASH' => /\A(?:\\)\z/, 'LEEF_DELIMITER_LITERAL' => /\A(?:[\t!-<>-\[\]-~])\z/, 'LEEF_HEX_DIGITS' => /\A(?:[0-9A-Fa-f]{1,4})\z/}
end

# src/grammar/extractEvent.ts: CSV_DELIMITERS
def psg_k_csv_delimiters
  @psg_k_csv_delimiters ||= [',', ';', "\u{9}"]
end

# src/grammar/lossGuard.ts: JSON_ESCAPES
def psg_k_json_escapes
  @psg_k_json_escapes ||= {'"' => '"', '\\' => '\\', '/' => '/', 'b' => "\u{8}", 'f' => "\u{c}", 'n' => "\u{a}", 'r' => "\u{d}", 't' => "\u{9}"}
end

# src/structuredFamilies.ts: LEEF_DELIMITER_VERSIONS
def psg_k_leef_delimiter_versions
  @psg_k_leef_delimiter_versions ||= ['2.0']
end

# src/grammar/lossGuard.ts: LEEF_DELIMITER_VERSIONS
def psg_k_leef_delimiter_versions_2
  @psg_k_leef_delimiter_versions_2 ||= ['2.0']
end

# src/structuredFamilies.ts: LEEF_EXTRA_DELIMITERS
def psg_k_leef_extra_delimiters
  @psg_k_leef_extra_delimiters ||= [166]
end

# src/grammar/lossGuard.ts: LEEF_HEADER_FIELDS
def psg_k_leef_header_fields
  @psg_k_leef_header_fields ||= ['leef_version', 'leef_vendor', 'leef_product', 'leef_product_version', 'leef_event_id']
end

# src/structuredFamilies.ts: LEEF_VERSIONS
def psg_k_leef_versions
  @psg_k_leef_versions ||= ['1.0', '2.0']
end

# src/grammar/extractEvent.ts: MIXED_FAMILIES
def psg_k_mixed_families
  @psg_k_mixed_families ||= ['json', 'kv', 'cef', 'leef', 'rfc5424_cef', 'rfc5424_leef', 'rfc3164_kv', 'rfc5424_json', 'rfc5424_kv', 'rfc3164_cef', 'rfc3164_leef', 'csv']
end

# src/grammar/sourceFieldNames.ts: RESERVED
def psg_k_reserved
  @psg_k_reserved ||= ['__proto__', 'constructor', 'prototype']
end

# src/grammar/syslogHeaderGrammar.generated.ts: SYSLOG_HEADER_ALTERNATIVES
def psg_k_syslog_header_alternatives
  @psg_k_syslog_header_alternatives ||= {'rfc3164' => ['rfc3164_tagged', 'rfc3164_tagless', 'rfc3164_hostless']}
end

# src/grammar/syslogHeaderGrammar.generated.ts: SYSLOG_HEADER_RULES
def psg_k_syslog_header_rules
  @psg_k_syslog_header_rules ||= {'rfc3164_tagged' => {'source' => '^(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?!(?:(?:CEF|LEEF))(?:(?:[ \\t]))*:(?:(?:[ \\t]))*(?:[0-9]))(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)$', 'captures' => ['pri', 'month', 'day', 'hour', 'minute', 'second', 'hostname', 'tag', 'procid', 'message']}, 'rfc3164_tagless' => {'source' => '^(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<message>[^\\r\\n]+)$', 'captures' => ['pri', 'month', 'day', 'hour', 'minute', 'second', 'hostname', 'message']}, 'rfc3164_hostless' => {'source' => '^(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)$', 'captures' => ['pri', 'month', 'day', 'hour', 'minute', 'second', 'message']}, 'rfc5424' => {'source' => '^<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?<timestamp>[!-~]{1,64})[ ](?<hostname>[!-~]{1,255})[ ](?<appname>[!-~]{1,48})[ ](?<procid>[!-~]{1,128})[ ](?<msgid>[!-~]{1,32})[ ](?<rest>[^\\r\\n]+)$', 'captures' => ['pri', 'version', 'timestamp', 'hostname', 'appname', 'procid', 'msgid', 'rest']}}
end

# src/grammar/syslogHeaderGrammar.generated.ts: SYSLOG_HEADER_SEMANTICS
def psg_k_syslog_header_semantics
  @psg_k_syslog_header_semantics ||= {'priMax' => 191, 'bsdMonthDays' => {'Jan' => 31, 'Feb' => 29, 'Mar' => 31, 'Apr' => 30, 'May' => 31, 'Jun' => 30, 'Jul' => 31, 'Aug' => 31, 'Sep' => 30, 'Oct' => 31, 'Nov' => 30, 'Dec' => 31}, 'rfc5424SupportedVersions' => ['1'], 'kvMaxPairs' => 100, 'kvForbiddenKeys' => ['__proto__', 'constructor', 'prototype'], 'kvUnescapedAfterBackslash' => ['\\', '"', '\'', '='], 'kvAsciiWhitespace' => [' ', "\u{9}", "\u{a}", "\u{d}", "\u{c}", "\u{b}"], 'cefSupportedVersions' => ['0'], 'cefMaxExtensionFields' => 1024, 'cefExtensionEscapes' => {'n' => "\u{a}", 'r' => "\u{d}", '=' => '=', '\\' => '\\'}, 'leefSupportedVersions' => ['1.0', '2.0'], 'leefDelimiterFieldVersions' => ['2.0'], 'leefDefaultDelimiter' => "\u{9}", 'leefHeaderFields' => 4, 'leefDelimiterExtraCodePoints' => [166]}
end

# src/grammar/kvBody.ts: UNESCAPED
def psg_k_unescaped
  @psg_k_unescaped ||= ['\\', '"', '\'', '=']
end

# src/structuredFamilies.ts: bodyKindOf
def psg_body_kind_of(extraction)
  psg_get_tag(extraction, 'bodyKind')
end

# src/structuredFamilies.ts: boundedJsonObject
def psg_bounded_json_object(text)
  parsed = nil
  begin
    parsed = psg_json_parse(text)
    if ((!psg_t(parsed) || !(psg_typeof(parsed) == 'object')) || parsed.is_a?(Array))
      return psg_failure_2('RFC5424 JSON body must be an object')
    end
    if psg_has_duplicate_json_object_keys(text)
      return psg_failure_2('Duplicate JSON object key in reviewed Syslog body')
    end
    if psg_has_unsafe_json_numbers(text)
      return psg_failure_2('Unsafe JSON numeric precision: quote large identifiers as strings')
    end
    if !psg_json_source_value_valid(parsed)
      return psg_failure_2('RFC5424 JSON body exceeds native nesting depth or contains invalid Unicode')
    end
    return {'fields' => psg_with_source_field_names(parsed), 'errors' => []}
  rescue StandardError
    return psg_failure_2('RFC5424 JSON body is not valid JSON')
  end
  nil
end

# src/grammar/lossGuard.ts: bump
def psg_bump(counts, token, delta)
  counts[token] = ((psg_null?(psg_t1 = counts[token]) ? 0 : psg_t1) + delta)
  nil
end

# src/grammar/lossGuard.ts: cefEventUnaccounted
def psg_cef_event_unaccounted(text, fields)
  cursor = length = blank = seen = key = value = index = valueStart = unit = escaped = nil
  cursor = psg_header_end(text, 'CEF:', psg_k_cef_header_fields, fields)
  if (cursor < 0)
    return 'a CEF header field is not the text of the event'
  end
  length = psg_len(text)
  blank = cursor
  while ((blank < length) && " \u{9}\u{a}\u{b}\u{c}\u{d}\u{0}".include?(psg_at(text, blank)))
    blank += 1
  end
  seen = 0
  while (blank < length)
    while ((cursor < length) && ((psg_at(text, cursor) == ' ') || (psg_at(text, cursor) == "\u{9}")))
      cursor += 1
    end
    if (cursor >= length)
      break
    end
    key = ''
    while ((((cursor < length) && (psg_at(text, cursor) != '=')) && (psg_at(text, cursor) != ' ')) && (psg_at(text, cursor) != "\u{9}"))
      key += psg_at(text, cursor)
      cursor += 1
    end
    if (psg_at(text, cursor) != '=')
      return 'text of the CEF extension is not part of any extracted field'
    end
    cursor += 1
    value = (psg_k_cef_header_fields.include?(key) ? nil : fields[psg_source_field_name(key)])
    if !value.is_a?(String)
      return 'a key=value pair of the CEF extension is missing from the extracted fields'
    end
    index = 0
    valueStart = cursor
    while (index < psg_len(value))
      unit = psg_at(text, cursor)
      if unit.nil?
        return 'an extracted CEF value is not the text of its key=value pair'
      end
      if (unit != '\\')
        if (psg_at(value, index) != unit)
          return 'an extracted CEF value is not the text of its key=value pair'
        end
        index += 1
        cursor += 1
        next
      end
      escaped = psg_at(text, (cursor + 1))
      if escaped.nil?
        return 'an extracted CEF value is not the text of its key=value pair'
      end
      if ((escaped == ' ') || (escaped == "\u{9}"))
        if (psg_at(value, index) != '\\')
          return 'an extracted CEF value is not the text of its key=value pair'
        end
        index += 1
        cursor += 1
        next
      end
      if psg_k_cef_escapes.key?(escaped)
        if (psg_at(value, index) != psg_k_cef_escapes[escaped])
          return 'an extracted CEF value is not the text of its key=value pair'
        end
        index += 1
      else
        if ((psg_at(value, index) != '\\') || (psg_at(value, (index + 1)) != escaped))
          return 'an extracted CEF value is not the text of its key=value pair'
        end
        index += 2
      end
      cursor += 2
    end
    seen += 1
    if (((cursor < length) && (psg_at(text, cursor) != ' ')) && (psg_at(text, cursor) != "\u{9}"))
      return 'an extracted CEF value ends before the text of its value does'
    end
    if /[ \t][A-Za-z_][A-Za-z0-9_.\-]{0,127}=/.match?(psg_slice(text, valueStart, cursor))
      return 'a key=value pair of the CEF extension is inside an extracted value'
    end
  end
  return ((fields.keys.length == (7 + seen)) ? :psg_null : 'an extracted field is not in the CEF extension')
end

# src/structuredFamilies.ts: cefExtensionValues
def psg_cef_extension_values(input)
  values = cursor = count = match = key = nil
  values = {}
  cursor = 0
  count = 0
  while true
    match = psg_match_at(/\G(?:(?:(?:[ \t]))*(?<key>[A-Za-z_][A-Za-z0-9_.\-]{0,127})=(?<value>(?:(?:(?:\\[^ \t])|(?:[^\\ \t])|(?:[ \t]+)(?=(?:[^ \t]))(?!(?:[A-Za-z_][A-Za-z0-9_.\-]{0,127})=)|(?:[ \t]+)(?=(?:[ \t])(?:[A-Za-z_][A-Za-z0-9_.\-]{0,127})=)|(?:\\)(?=(?:[ \t]))))*)(?:(?:(?:[ \t]))*\z|(?:[ \t])(?=(?:[A-Za-z_][A-Za-z0-9_.\-]{0,127})=)))/, input, cursor)
    if !psg_t(match)
      break
    end
    if (((count += 1) - 1) >= 1024)
      return psg_failure_2('CEF extension field limit exceeded')
    end
    key = psg_source_field_name(psg_group(match, 'key'))
    if values.key?(key)
      return psg_failure_2(psg_duplicate_field_message(key))
    end
    values[key] = psg_decode_cef_value(psg_group(match, 'value'))
    cursor = psg_match_end(match)
  end
  if (cursor != psg_len(input))
    return psg_failure_2('Unsupported CEF extension key boundary')
  end
  if !psg_t(values.keys.length)
    return psg_failure_2('No CEF extension fields parsed')
  end
  return {'fields' => values, 'errors' => []}
end

# src/grammar/parseStatus.ts: classifyStructuredParse
def psg_classify_structured_parse(raw, outcome, bodyFormat)
  host = headerReasons = body = scope = leaves = taken = lostPairs = nil
  if outcome.key?('thrown')
    return {'status' => 'ERROR', 'lostPairs' => [], 'reasons' => [('extractor raised: ' + psg_str(outcome['thrown']))]}
  end
  if (outcome['errors'].length > 0)
    return {'status' => 'UNKNOWN', 'lostPairs' => [], 'reasons' => psg_slice(outcome['errors'], 0, 4)}
  end
  if (outcome['fields'].keys.length == 0)
    return {'status' => 'UNKNOWN', 'lostPairs' => [], 'reasons' => ['no field was extracted']}
  end
  host = ((psg_get_tag(outcome, 'rfc3164Header') == true) ? outcome['fields']['syslog_hostname'] : nil)
  headerReasons = ((host.is_a?(String) && (host.include?('=') || host.end_with?(':'))) ? ['a TAG or a key=value pair was taken as the host name'] : [])
  if (bodyFormat != 'kv')
    return {'status' => (psg_t(headerReasons.length) ? 'PARTIAL' : 'FULL'), 'lostPairs' => [], 'reasons' => headerReasons}
  end
  body = outcome['fields']['body']
  scope = (((!body.equal?(:psg_null) && (psg_typeof(body) == 'object')) && !body.is_a?(Array)) ? body : outcome['fields'])
  leaves = {}
  psg_collect_leaves(scope, '', leaves)
  taken = {}
  lostPairs = psg_filter(psg_independent_key_value_pairs(raw), lambda { |pair|
  field = values = consumed = at = nil
  field = psg_source_field_name(pair['key'])
  values = (psg_null?(psg_t1 = leaves[field]) ? [] : psg_t1)
  consumed = (psg_null?(psg_t2 = taken[field]) ? {} : psg_t2)
  at = psg_find_index(values, lambda { |value, index| (!consumed.key?(index) && (pair['quoted'] ? (((value == pair['value']) || (value == pair['rawValue'])) || (psg_join(psg_split(value, '\\'), '') == psg_join(psg_split(pair['rawValue'], '\\'), ''))) : (value == pair['rawValue']))) })
  if (at < 0)
    return true
  end
  consumed[at] = true
  taken[field] = consumed
  return false
})
  if ((lostPairs.length > 0) || (headerReasons.length > 0))
    return {'status' => 'PARTIAL', 'lostPairs' => lostPairs, 'reasons' => [*headerReasons, *psg_map(psg_slice(lostPairs, 0, 4), lambda { |pair_2| ('raw pair ' + pair_2['key'] + '= is not present with its value in the extracted fields') })]}
  end
  return {'status' => 'FULL', 'lostPairs' => [], 'reasons' => []}
end

# src/grammar/parseStatus.ts: closingQuote
def psg_closing_quote(raw, quote, from)
  at = run = nil
  at = psg_index(raw, quote, from)
  while (at >= 0)
    run = 0
    while ((((at - 1) - run) >= from) && (psg_at(raw, ((at - 1) - run)) == '\\'))
      run += 1
    end
    if (psg_mod(run, 2) == 0)
      return at
    end
    at = psg_index(raw, quote, (at + 1))
  end
  return (-1)
end

# src/grammar/parseStatus.ts: collectLeaves
def psg_collect_leaves(value, key, out)
  list = nil
  if value.is_a?(Array)
    value.each do |child|
      psg_collect_leaves(child, key, out)
    end
    return nil
  end
  if (!value.equal?(:psg_null) && (psg_typeof(value) == 'object'))
    value.to_a.each do |(childKey, child_2)|
      psg_collect_leaves(child_2, childKey, out)
    end
    return nil
  end
  if (value.nil? || value.equal?(:psg_null))
    return nil
  end
  list = out[key]
  if list
    list.push(psg_str(value))
  else
    out[key] = [psg_str(value)]
  end
  nil
end

# src/grammar/lossGuard.ts: countJsonTextTokens
def psg_count_json_text_tokens(text, counts)
  length = hex = index = char = value = unit = escape = code = low = digits = literal = nil
  length = psg_len(text)
  hex = lambda { |at| psg_parse_int(((((psg_null?(psg_t1 = psg_at(text, at)) ? '' : psg_t1) + (psg_null?(psg_t2 = psg_at(text, (at + 1))) ? '' : psg_t2)) + (psg_null?(psg_t3 = psg_at(text, (at + 2))) ? '' : psg_t3)) + (psg_null?(psg_t4 = psg_at(text, (at + 3))) ? '' : psg_t4)), 16) }
  index = 0
  while (index < length)
    char = psg_at(text, index)
    if (char == '"')
      value = ''
      index += 1
      while true
        if (index >= length)
          return false
        end
        unit = psg_at(text, index)
        if (unit == '"')
          index += 1
          break
        end
        if (unit != '\\')
          value += unit
          index += 1
          next
        end
        escape = (psg_null?(psg_t5 = psg_at(text, (index + 1))) ? '' : psg_t5)
        if (escape != 'u')
          if !psg_k_json_escapes.key?(escape)
            return false
          end
          value += psg_k_json_escapes[escape]
          index += 2
          next
        end
        code = hex.call((index + 2))
        if ((((code >= 55296) && (code <= 56319)) && (psg_at(text, (index + 6)) == '\\')) && (psg_at(text, (index + 7)) == 'u'))
          low = hex.call((index + 8))
          if !((low >= 56320) && (low <= 57343))
            return false
          end
          value += psg_from_code_point(((65536 + psg_mul((code - 55296), 1024)) + (low - 56320)))
          index += 12
        else
          if (!(code >= 0) || ((code >= 55296) && (code <= 57343)))
            return false
          end
          value += psg_from_code_point(code)
          index += 6
        end
      end
      psg_bump(counts, ('s:' + value), 1)
    elsif '-0123456789'.include?(char)
      digits = char
      index += 1
      while ((index < length) && '0123456789eE+-.'.include?(psg_at(text, index)))
        digits += psg_at(text, index)
        index += 1
      end
      psg_bump(counts, ('n:' + psg_str(psg_num(digits))), 1)
    elsif (((char == 't') || (char == 'f')) || (char == 'n'))
      literal = ((char == 't') ? 'true' : ((char == 'f') ? 'false' : 'null'))
      psg_bump(counts, ('l:' + literal), 1)
      index += psg_len(literal)
    else
      index += 1
    end
  end
  return true
end

# src/grammar/lossGuard.ts: countJsonValueTokens
def psg_count_json_value_tokens(value, counts)
  if value.is_a?(Array)
    value.each do |item|
      psg_count_json_value_tokens(item, counts)
    end
    return nil
  end
  if (!value.equal?(:psg_null) && (psg_typeof(value) == 'object'))
    psg_entries(value).each do |(name, item_2)|
      psg_bump(counts, ('s:' + psg_original_field_name(name)), (-1))
      psg_count_json_value_tokens(item_2, counts)
    end
    return nil
  end
  if value.is_a?(String)
    psg_bump(counts, ('s:' + value), (-1))
  elsif value.is_a?(Numeric)
    psg_bump(counts, ('n:' + psg_str(value)), (-1))
  else
    psg_bump(counts, ('l:' + psg_str(value)), (-1))
  end
  nil
end

# src/grammar/lossGuard.ts: csvRowUnaccounted
def psg_csv_row_unaccounted(text, delimiter, cells)
  return psg_row_unaccounted(text, delimiter, cells, (delimiter != "\u{9}"))
end

# src/jsonNumberSafety.ts: decimalIdentity
def psg_decimal_identity(spelling)
  parts = mantissa = exponent = point = whole = fraction = digits = trimmed = nil
  parts = psg_split(spelling, /[eE]/)
  mantissa = psg_replace(parts[0], /\A[+\-]/, false, '')
  exponent = ((parts.length > 1) ? psg_num(parts[1]) : 0)
  point = psg_index(mantissa, '.')
  whole = ((point < 0) ? mantissa : psg_slice(mantissa, 0, point))
  fraction = ((point < 0) ? '' : psg_slice(mantissa, (point + 1)))
  digits = psg_replace((whole + fraction), /\A0+/, false, '')
  trimmed = psg_replace(digits, /0+\z/, false, '')
  if (trimmed == '')
    return '0'
  end
  return ((trimmed + 'e') + psg_str(((exponent - psg_len(fraction)) + (psg_len(digits) - psg_len(trimmed)))))
end

# src/structuredFamilies.ts: decodeCefValue
def psg_decode_cef_value(raw)
  psg_replace(raw, /\\[^ \t]/, true, lambda { |pair| (psg_k_cef_escapes_2.key?(psg_at(pair, 1)) ? psg_k_cef_escapes_2[psg_at(pair, 1)] : pair) })
end

# src/structuredFamilies.ts: deterministicBody
def psg_deterministic_body(text)
  if /\ACEF:/.match?(text)
    return 'cef'
  end
  if /\ALEEF:/.match?(text)
    return 'leef'
  end
  if text.start_with?('{')
    return 'json'
  end
  if /\A[A-Za-z_][A-Za-z0-9_.\-]*=/.match?(text)
    return 'kv'
  end
  return 'raw'
end

# src/structuredFamilies.ts: duplicateFieldMessage
def psg_duplicate_field_message(key)
  (('Duplicate field "' + key) + '": the same name appears more than once in the event. No value is overwritten, and the event is not parsed automatically.')
end

# src/javaStacktrace.ts: error
def psg_error()
  {'fields' => {}, 'errors' => ['Java exception does not match the bounded TCP blank-line-framed grammar']}
end

# src/grammar/extractEvent.ts: extractCsvRow
def psg_extract_csv_row(raw, columns, delimiter)
  values = fields = index = result = nil
  if !psg_k_csv_delimiters.include?(delimiter)
    return psg_failure('Unsupported CSV data delimiter')
  end
  if (((!psg_t(columns.length) || (columns.length > 100)) || psg_some(columns, lambda { |name| !/\A[A-Za-z][A-Za-z0-9_]{0,63}\z/.match?(name) })) || (psg_set(columns).length != columns.length))
    return psg_failure('Provide unique valid CSV column names')
  end
  values = psg_tokenize_csv_row(raw, delimiter)
  if !psg_t(values)
    return psg_failure('Malformed CSV quotation or unsupported delimiter')
  end
  if (values.length != columns.length)
    return psg_failure(((('CSV column count mismatch: expected ' + psg_str(columns.length)) + ', received ') + psg_str(values.length)))
  end
  fields = {}
  index = 0
  while (index < columns.length)
    fields[psg_at(columns, index)] = psg_at(values, index)
    index += 1
  end
  result = {'fields' => fields, 'errors' => []}
  psg_set_tag(result, 'bodyKind', 'csv')
  return result
end

# src/grammar/extractEvent.ts: extractEvent
def psg_extract_event(raw, settings)
  v_format = nil
  v_format = settings['format']
  if (v_format == 'json')
    return psg_extract_json_object(raw)
  end
  if (v_format == 'kv')
    return psg_strict_key_values(raw)
  end
  if (v_format == 'csv')
    return psg_extract_csv_row(raw, (psg_null?(psg_t1 = settings['csvColumns']) ? [] : psg_t1), (psg_null?(psg_t2 = settings['csvDelimiter']) ? ',' : psg_t2))
  end
  if (v_format == 'java_stacktrace')
    return psg_parse_java_stacktrace(raw)
  end
  if (v_format == 'generic_structural')
    return psg_extract_generic_structural(raw, settings['genericStructuralProfile'], settings['genericStructuralFamilyGrammar'])
  end
  if (v_format == 'mixed')
    return psg_extract_mixed(raw, settings)
  end
  if ((v_format == 'syslog_rfc3164') || (v_format == 'syslog_rfc5424'))
    return psg_extract_structured_family(raw, v_format, (psg_null?(psg_t3 = settings['syslogBodyFormat']) ? 'raw' : psg_t3), settings['pattern'])
  end
  if ((v_format == 'cef') || (v_format == 'leef'))
    return psg_extract_standalone_family(raw, v_format)
  end
  if (v_format == 'regex')
    return psg_x_portable_regex_fields(raw, (psg_null?(psg_t4 = settings['pattern']) ? '' : psg_t4))
  end
  return psg_failure('Unsupported extraction format')
end

# src/grammar/extractEvent.ts: extractJsonObject
def psg_extract_json_object(raw)
  parsed = result = nil
  begin
    parsed = psg_json_parse(raw)
    if ((!psg_t(parsed) || parsed.is_a?(Array)) || !(psg_typeof(parsed) == 'object'))
      return psg_failure('JSON event must be an object')
    end
    if psg_has_duplicate_json_object_keys(raw)
      return psg_failure('Duplicate JSON object key: review the source before generating a parser')
    end
    if psg_has_unsafe_json_numbers(raw)
      return psg_failure('Unsafe JSON numeric precision: quote large integer identifiers as strings before mapping')
    end
    if !psg_json_source_value_valid(parsed)
      return psg_failure('JSON source exceeds the native nesting limit or has an invalid Unicode surrogate')
    end
    result = {'fields' => psg_with_source_field_names(parsed), 'errors' => []}
    psg_set_tag(result, 'bodyKind', 'json')
    return result
  rescue StandardError
    return psg_failure('Invalid JSON object')
  end
  nil
end

# src/grammar/extractEvent.ts: extractMixed
def psg_extract_mixed(raw, settings)
  selected = bsdEnvelope = grammar = message = header = header_2 = body = mode = columns = delimiter = family = nil
  selected = (psg_null?(psg_t1 = settings['mixedFormats']) ? [] : psg_t1)
  if ((((selected.length < 2) || (selected.length > 4)) || (psg_set(selected).length != selected.length)) || psg_some(selected, lambda { |family_2| !psg_k_mixed_families.include?(family_2) }))
    return psg_failure('Select an explicit bounded mixed-family allowlist')
  end
  bsdEnvelope = /\A(?:<[0-9]{1,3}>)?[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:/.match?(raw)
  if (((!raw.start_with?('{') && !raw.start_with?('CEF:')) && !raw.start_with?('LEEF:')) && (bsdEnvelope || raw.start_with?('<')))
    grammar = (bsdEnvelope ? 'syslog_rfc3164' : 'syslog_rfc5424')
    message = nil
    if bsdEnvelope
      header = psg_match_rfc3164_header(raw)
      message = (header['ok'] ? header['message'] : nil)
    else
      header_2 = psg_extract_structured_family(raw, grammar, 'raw')
      message = (psg_t(header_2['errors'].length) ? nil : header_2['fields']['message'])
    end
    body = (!message.is_a?(String) ? :psg_null : (message.start_with?('CEF:') ? 'cef' : (message.start_with?('LEEF:') ? 'leef' : ((!bsdEnvelope && message.start_with?('{')) ? 'json' : (/\A[A-Za-z_][A-Za-z0-9_.\-]*=/.match?(message) ? 'kv' : :psg_null)))))
    mode = (psg_t(body) ? (((bsdEnvelope ? 'rfc3164' : 'rfc5424') + '_') + body) : :psg_null)
    if ((!psg_t(body) || !psg_t(mode)) || !selected.include?(mode))
      return psg_failure((bsdEnvelope ? 'RFC3164 TAG body is unsupported or not allowlisted' : 'Wrapped Syslog is malformed or not in mixed allowlist'))
    end
    return psg_mixed_family(psg_extract_structured_family(raw, grammar, body), mode)
  end
  columns = (psg_null?(psg_t2 = settings['csvColumns']) ? [] : psg_t2)
  delimiter = (psg_null?(psg_t3 = settings['csvDelimiter']) ? ',' : psg_t3)
  family = (raw.start_with?('{') ? 'json' : (raw.start_with?('CEF:') ? 'cef' : (raw.start_with?('LEEF:') ? 'leef' : (/\A[A-Za-z_][A-Za-z0-9_.\-]*=/.match?(raw) ? 'kv' : (((selected.include?('csv') && (columns.length >= 2)) && raw.include?(delimiter)) ? 'csv' : :psg_null)))))
  if (!psg_t(family) || !selected.include?(family))
    return psg_failure('Mixed event is unsupported or excluded by allowlist')
  end
  if (family == 'kv')
    return psg_mixed_family(psg_strict_key_values(raw), family)
  end
  if (family == 'csv')
    return psg_mixed_family(psg_extract_csv_row(raw, columns, delimiter), family)
  end
  if (family == 'json')
    return psg_mixed_family(psg_extract_json_object(raw), family)
  end
  return psg_mixed_family(psg_extract_structured_family(raw, family), family)
end

# src/structuredFamilies.ts: extractStandaloneFamily
def psg_extract_standalone_family(input, v_format)
  prefix = text = nested = result = nil
  prefix = psg_pri_only_prefix(input)
  if prefix.equal?(:psg_null)
    return psg_extract_structured_family(input, v_format)
  end
  if (prefix['family'] != v_format)
    return psg_failure_2(((v_format == 'cef') ? 'A LEEF event is not a CEF event' : 'A CEF event is not a LEEF event'))
  end
  text = psg_slice(input, prefix['end'])
  nested = psg_extract_structured_family(text, v_format)
  if (nested['errors'].length > 0)
    return nested
  end
  result = psg_with_body_kind({'fields' => {'syslog_pri' => prefix['pri'], 'body' => nested['fields']}, 'errors' => []}, v_format)
  psg_set_tag(result, 'bodyText', text)
  return result
end

# src/structuredFamilies.ts: extractStructuredFamily
def psg_extract_structured_family(input, v_format, bodyFormat = nil, regexPattern = nil)
  scanned = body = bodyKind = mode = nested = result = match = parts = record = extension = match_2 = carriesDelimiter = headerFields = parts_2 = delimiter = record_2 = attribute = name = key = nil
  bodyFormat = 'raw' if bodyFormat.nil?
  if (input.include?("\u{a}") || input.include?("\u{d}"))
    return psg_failure_2('Only one logical record per physical line is supported for pairing.')
  end
  if (v_format == 'syslog_rfc3164')
    return psg_parse_rfc3164_strict(input, bodyFormat, regexPattern)
  end
  if (v_format == 'syslog_rfc5424')
    scanned = psg_parse_rfc5424_subset(input)
    if !scanned['ok']
      return psg_failure_2(scanned['error'])
    end
    body = {}
    bodyKind = nil
    if psg_t(scanned['message'])
      mode = ((bodyFormat == 'auto') ? psg_deterministic_body(scanned['message']) : bodyFormat)
      bodyKind = mode
      if (mode == 'raw')
        body['message'] = scanned['message']
      elsif ['json', 'kv', 'cef', 'leef', 'regex'].include?(mode)
        nested = ((mode == 'json') ? psg_bounded_json_object(scanned['message']) : ((mode == 'kv') ? psg_strict_key_values(scanned['message']) : ((mode == 'regex') ? psg_regex_body(scanned['message'], regexPattern) : psg_extract_structured_family(scanned['message'], mode))))
        if (nested['errors'].length > 0)
          return nested
        end
        body['body'] = nested['fields']
      else
        return psg_failure_2('Unsupported RFC5424 body dialect')
      end
    end
    result = psg_with_body_kind({'fields' => {}.merge!(scanned['fields']).merge!(body), 'errors' => []}, bodyKind)
    if psg_t(scanned['message'])
      psg_set_tag(result, 'bodyText', scanned['message'])
    end
    return result
  end
  if (v_format == 'cef')
    match = (/\ACEF: ?([0-9]+)\|((?m:.)*)\z/.match(input) || :psg_null)
    if (!psg_t(match) || !psg_k_cef_versions.include?(match[1]))
      return psg_failure_2('Only standalone CEF version zero events are supported')
    end
    parts = psg_split_escaped(match[2], '|', 6)
    if !psg_t(parts)
      return psg_failure_2('CEF requires six header fields and an extension slot')
    end
    record = {'cef_version' => match[1], 'cef_device_vendor' => parts[0], 'cef_device_product' => parts[1], 'cef_device_version' => parts[2], 'cef_signature_id' => parts[3], 'cef_name' => parts[4], 'cef_severity' => parts[5]}
    if /[^ \t\n\x0b\f\r\x00]/.match?(parts[6])
      extension = psg_cef_extension_values(parts[6])
      if psg_t(extension['errors'].length)
        return extension
      end
      extension['fields'].to_a.each do |(key_2, value)|
        if record.key?(key_2)
          return psg_failure_2('Extension overrides a reserved CEF header field')
        end
        record[key_2] = value
      end
    end
    return psg_with_body_kind({'fields' => record, 'errors' => []}, 'cef')
  end
  match_2 = (/\ALEEF:([0-9.]+)\|((?m:.)*)\z/.match(input) || :psg_null)
  if (!psg_t(match_2) || !psg_k_leef_versions.include?(match_2[1]))
    return psg_failure_2('Only standalone LEEF 1.0 or 2.0 events are supported')
  end
  carriesDelimiter = psg_k_leef_delimiter_versions.include?(match_2[1])
  headerFields = 4
  parts_2 = psg_split_escaped(match_2[2], '|', (headerFields + (carriesDelimiter ? 1 : 0)))
  if !psg_t(parts_2)
    return psg_failure_2('LEEF header or declared delimiter is incomplete')
  end
  delimiter = psg_leef_delimiter((carriesDelimiter ? psg_at(parts_2, headerFields) : nil))
  if delimiter.equal?(:psg_null)
    return psg_failure_2('Unsupported LEEF 2.0 data delimiter')
  end
  record_2 = psg_assign({}, {'leef_version' => match_2[1], 'leef_vendor' => parts_2[0], 'leef_product' => parts_2[1], 'leef_product_version' => parts_2[2], 'leef_event_id' => parts_2[3]})
  if psg_t(psg_at(parts_2, (parts_2.length - 1)))
    psg_split(psg_at(parts_2, (parts_2.length - 1)), delimiter).each do |part|
      attribute = psg_match_at(/\G(?:(?<key>[A-Za-z_][A-Za-z0-9_.\-]*)=)/, part, 0)
      name = psg_group(attribute, 'key')
      if (!psg_t(attribute) || name.nil?)
        return psg_failure_2('Unsupported LEEF extension token')
      end
      key = psg_source_field_name(name)
      if record_2.key?(key)
        return psg_failure_2(psg_duplicate_field_message(key))
      end
      record_2[key] = psg_slice(part, psg_match_end(attribute))
    end
  end
  return psg_with_body_kind({'fields' => record_2, 'errors' => []}, 'leef')
end

# src/grammar/extractEvent.ts: failure
def psg_failure(message)
  {'fields' => {}, 'errors' => [message]}
end

# src/structuredFamilies.ts: failure
def psg_failure_2(message)
  {'fields' => {}, 'errors' => [message]}
end

# src/grammar/readEvent.ts: gradeExtraction
def psg_grade_extraction(raw, settings, extraction)
  keyValueBody = verdict = reason = claim = nil
  if (settings['format'] == 'generic_structural')
    return psg_classify_generic_structural(raw, extraction)
  end
  keyValueBody = (((settings['format'] == 'kv') || (psg_body_kind_of(extraction) == 'kv')) || (((settings['format'] == 'syslog_rfc3164') || (settings['format'] == 'syslog_rfc5424')) && (settings['syslogBodyFormat'] == 'kv')))
  verdict = psg_classify_structured_parse(raw, extraction, (keyValueBody ? 'kv' : 'other'))
  if (verdict['status'] != 'FULL')
    return verdict
  end
  reason = psg_unaccounted_text(raw, settings, extraction)
  if !reason.equal?(:psg_null)
    return {'status' => 'PARTIAL', 'lostPairs' => [], 'reasons' => [reason]}
  end
  claim = psg_malformed_family_claim(settings, extraction)
  if (claim == '')
    return verdict
  end
  return {'status' => 'PARTIAL', 'lostPairs' => [], 'textKept' => true, 'reasons' => [(((('the message claims to be ' + claim) + ' but has no valid ') + claim) + ' header; it is kept as text')]}
end

# src/jsonDuplicateKeys.ts: hasDuplicateJsonObjectKeys
def psg_has_duplicate_json_object_keys(source)
  stack = index = char = start = byte = v_end = scope = lookahead = name = nil
  stack = []
  index = 0
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else index += 1 end
    break unless (index < psg_len(source))
    char = psg_char_code_at(source, index)
    if (char == 123)
      stack.push({})
      next
    end
    if (char == 91)
      stack.push(:psg_null)
      next
    end
    if ((char == 125) || (char == 93))
      stack.pop
      next
    end
    if (char != 34)
      next
    end
    start = index
    index += 1
    while (index < psg_len(source))
      byte = psg_char_code_at(source, index)
      if (byte == 92)
        index += 2
        next
      end
      if (byte == 34)
        break
      end
      index += 1
    end
    v_end = (index + 1)
    scope = psg_at(stack, (stack.length - 1))
    if !psg_t(scope)
      next
    end
    lookahead = v_end
    while ((lookahead < psg_len(source)) && [9, 10, 13, 32].include?(psg_char_code_at(source, lookahead)))
      lookahead += 1
    end
    if (psg_char_code_at(source, lookahead) != 58)
      next
    end
    name = psg_json_parse(psg_slice(source, start, v_end))
    if scope.key?(name)
      return true
    end
    scope[name] = true
  end
  return false
end

# src/jsonNumberSafety.ts: hasUnsafeJsonNumbers
def psg_has_unsafe_json_numbers(source)
  index = current = match = token = value = mantissa = nil
  index = 0
  while (index < psg_len(source))
    current = psg_at(source, index)
    if (current == '"')
      index += 1
      while (index < psg_len(source))
        if (psg_at(source, index) == '\\')
          index += 2
          next
        end
        if (psg_at(source, ((index += 1) - 1)) == '"')
          break
        end
      end
      next
    end
    if ((current == '-') || ((current >= '0') && (current <= '9')))
      match = (/\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+\-]?[0-9]+)?/.match(psg_slice(source, index)) || :psg_null)
      if !psg_t(match)
        return true
      end
      token = match[0]
      value = psg_num(token)
      if !psg_finite?(value)
        return true
      end
      if (psg_integer?(value) && !psg_safe_integer?(value))
        return true
      end
      if /[.eE]/.match?(token)
        mantissa = psg_split(token, /[eE]/, 1)[0]
        if (psg_decimal_identity(token) != psg_decimal_identity(psg_str(value)))
          return true
        end
        if ((value == 0) && /[1-9]/.match?(mantissa))
          return true
        end
      end
      index += psg_len(token)
      next
    end
    index += 1
  end
  return false
end

# src/grammar/lossGuard.ts: headerEnd
def psg_header_end(text, prefix, names, fields)
  version = lead = cursor = index = field = nil
  version = fields[names[0]]
  if !version.is_a?(String)
    return (-1)
  end
  lead = (text.start_with?(((prefix + version) + '|')) ? prefix : (((prefix == 'CEF:') && text.start_with?((((prefix + ' ') + version) + '|'))) ? (prefix + ' ') : :psg_null))
  if lead.equal?(:psg_null)
    return (-1)
  end
  cursor = ((psg_len(lead) + psg_len(version)) + 1)
  index = 1
  while (index < names.length)
    field = psg_header_field_at(text, cursor)
    if (field.equal?(:psg_null) || (fields[psg_at(names, index)] != field['value']))
      return (-1)
    end
    cursor = field['next']
    index += 1
  end
  return cursor
end

# src/grammar/lossGuard.ts: headerFieldAt
def psg_header_field_at(text, from)
  value = at = unit = escaped = nil
  value = ''
  at = from
  while true
    unit = psg_at(text, at)
    if unit.nil?
      return :psg_null
    end
    if (unit == '|')
      return {'value' => value, 'next' => (at + 1)}
    end
    if (unit != '\\')
      value += unit
      at += 1
      next
    end
    escaped = psg_at(text, (at + 1))
    if escaped.nil?
      return :psg_null
    end
    value += (((escaped == '|') || (escaped == '\\')) ? escaped : ('\\' + escaped))
    at += 2
  end
  nil
end

# src/grammar/parseStatus.ts: independentKeyValuePairs
def psg_independent_key_value_pairs(raw)
  bareGaps = whole = nil
  bareGaps = []
  whole = psg_read_raw_pairs(raw, false, bareGaps)
  return ((bareGaps.length > 0) ? whole : psg_read_raw_pairs(raw, true, bareGaps))
end

# src/guided/declaredForwarder.ts: inspectDeclaredForwarders
def psg_inspect_declared_forwarders(raw, config = nil)
  direct = unsafe = text = startByte = hops = i = envelope = offset = nil
  direct = {'status' => 'DIRECT', 'payload' => raw, 'payloadStartByte' => 0, 'hops' => [], 'reason' => 'NO_DECLARED_RELAY'}
  if !config
    return direct
  end
  unsafe = lambda { |reason| {'status' => 'ABSTAIN_UNSAFE', 'payload' => raw, 'payloadStartByte' => 0, 'hops' => [], 'reason' => reason} }
  if ((((!psg_valid_forwarder_config(config) || (raw.bytesize > 65536)) || raw.include?("\u{0}")) || raw.include?("\u{a}")) || raw.include?("\u{d}"))
    return unsafe.call('UNSAFE_RELAY_SOURCE_OR_PROFILE')
  end
  text = raw
  startByte = 0
  hops = []
  i = 0
  while (i <= config['maxHops'])
    if !text.start_with?('<')
      break
    end
    envelope = psg_single_envelope(text)
    if !psg_t(envelope)
      break
    end
    if !config['relayHosts'].include?(envelope['host'])
      break
    end
    if (i == config['maxHops'])
      return unsafe.call('DECLARED_RELAY_HOP_LIMIT_EXCEEDED')
    end
    if ((!psg_t(envelope['payload']) || !text.end_with?(envelope['payload'])) || (envelope['payload'].bytesize >= text.bytesize))
      return unsafe.call('UNREPLAYABLE_RELAY_BODY')
    end
    offset = (text.bytesize - envelope['payload'].bytesize)
    hops.push({'relayHost' => envelope['host'], 'relayTimestamp' => envelope['timestamp'], 'format' => envelope['format'], 'prefixStartByte' => startByte, 'payloadStartByte' => (startByte + offset)})
    startByte += offset
    text = envelope['payload']
    i += 1
  end
  return (psg_t(hops.length) ? {'status' => 'UNWRAPPED', 'payload' => text, 'payloadStartByte' => startByte, 'hops' => hops, 'reason' => 'DECLARED_SYSLOG_RELAY'} : direct)
end

# src/grammar/kvBody.ts: isDelimitedPairList
def psg_is_delimited_pair_list(input)
  delimiter = count = cursor = match = separator = found = nil
  delimiter = ''
  count = 0
  cursor = 0
  while (cursor <= psg_len(input))
    match = psg_match_at(/\G(?:(?:[ \t]*)(?<key>[A-Za-z_][A-Za-z0-9_.\-]{0,95})=(?:"(?<dq>[^"]*)"|'(?<sq>[^']*)'|(?<bare>[^ \t\n\r\f\x0b\x1c-\x1f"',;|=]+)))/, input, cursor)
    if (!psg_t(match) || (psg_match_end(match) <= cursor))
      return false
    end
    count += 1
    if (count > 100)
      return true
    end
    cursor = psg_match_end(match)
    if /\A(?:[ \t\n\r\f\x0b]*)\z/.match?(psg_slice(input, cursor))
      return (count >= 2)
    end
    separator = psg_match_at(/\G(?:(?<delimiter>[,;|]))/, input, cursor)
    if !psg_t(separator)
      return false
    end
    found = psg_group(separator, 'delimiter')
    if ((delimiter != '') && (found != delimiter))
      return false
    end
    delimiter = found
    cursor = psg_match_end(separator)
  end
  return false
end

# src/grammar/parseStatus.ts: isListDelimiter
def psg_is_list_delimiter(ch)
  return (((ch == ',') || (ch == ';')) || (ch == '|'))
end

# src/grammar/syslogHeader.ts: isSupportedRfc5424Version
def psg_is_supported_rfc5424_version(version)
  return psg_k_syslog_header_semantics['rfc5424SupportedVersions'].include?(version)
end

# src/jsonSourceSafety.ts: jsonSourceValueValid
def psg_json_source_value_valid(value, maxDepth = nil)
  pairs = pending = current = nil
  maxDepth = 8 if maxDepth.nil?
  pairs = lambda { |s|
  i = unit = v_next = nil
  i = 0
  while (i < psg_len(s))
    unit = psg_char_code_at(s, i)
    if ((unit >= 55296) && (unit <= 56319))
      v_next = (((i + 1) < psg_len(s)) ? psg_char_code_at(s, (i += 1)) : (-1))
      if ((v_next < 56320) || (v_next > 57343))
        return false
      end
    elsif ((unit >= 56320) && (unit <= 57343))
      return false
    end
    i += 1
  end
  return true
}
  pending = [{'value' => value, 'depth' => 0}]
  while psg_t(pending.length)
    current = pending.pop
    if (current['depth'] > maxDepth)
      return false
    end
    if (current['value'].is_a?(String) && !pairs.call(current['value']))
      return false
    end
    if (!current['value'].equal?(:psg_null) && (psg_typeof(current['value']) == 'object'))
      psg_entries(current['value']).each do |(key, entry)|
        if !pairs.call(key)
          return false
        end
        pending.push({'value' => entry, 'depth' => (current['depth'] + 1)})
      end
    end
  end
  return true
end

# src/grammar/lossGuard.ts: jsonTextUnaccounted
def psg_json_text_unaccounted(text, fields)
  counts = nil
  counts = {}
  if !psg_count_json_text_tokens(text, counts)
    return 'the JSON text could not be read a second time'
  end
  psg_count_json_value_tokens(fields, counts)
  counts.to_a.each do |(_token, count)|
    if (count > 0)
      return 'a name or value of the JSON text is missing from the extracted fields'
    end
    if (count < 0)
      return 'an extracted field holds a name or value that is not in the JSON text'
    end
  end
  return :psg_null
end

# src/grammar/parseStatus.ts: keyStartsAt
def psg_key_starts_at(raw, at, v_end)
  key = nil
  key = psg_match_at(/\G(?:[A-Za-z_][A-Za-z0-9_.\-]{0,95}=)/, raw, at)
  return (!key.equal?(:psg_null) && (psg_match_end(key) <= v_end))
end

# src/structuredFamilies.ts: leefDelimiter
def psg_leef_delimiter(field = nil)
  match = code = named = valid = nil
  if field.nil?
    return "\u{9}"
  end
  match = psg_match_at(/\G(?:(?:(?<literal>[\t!-<>-\[\]-~])|(?:0x|x)(?<hex>[0-9A-Fa-f]{1,4}))\z)/, field, 0)
  if !psg_group(match, 'literal').nil?
    return psg_group(match, 'literal')
  end
  code = (psg_t(match) ? psg_parse_int(psg_group(match, 'hex'), 16) : (([*field.chars].length == 1) ? psg_code_point_at(field, 0) : (-1)))
  if psg_k_leef_extra_delimiters.include?(code)
    return psg_from_code_point(code)
  end
  if (!psg_t(match) || (code > 126))
    return :psg_null
  end
  named = psg_from_code_point(code)
  valid = psg_match_at(/\G(?:(?:(?<literal>[\t!-<>-\[\]-~])|(?:0x|x)(?<hex>[0-9A-Fa-f]{1,4}))\z)/, named, 0)
  return ((psg_t(valid) && !psg_group(valid, 'literal').nil?) ? named : :psg_null)
end

# src/grammar/lossGuard.ts: leefEventUnaccounted
def psg_leef_event_unaccounted(text, fields)
  cursor = delimiter = declared = spelled = code = length = seen = key = value = nil
  cursor = psg_header_end(text, 'LEEF:', psg_k_leef_header_fields, fields)
  if (cursor < 0)
    return 'a LEEF header field is not the text of the event'
  end
  delimiter = "\u{9}"
  if psg_k_leef_delimiter_versions_2.include?(psg_str(fields['leef_version']))
    declared = psg_header_field_at(text, cursor)
    if declared.equal?(:psg_null)
      return 'the LEEF delimiter field is incomplete'
    end
    cursor = declared['next']
    spelled = declared['value']
    if (psg_len(spelled) == 1)
      delimiter = spelled
    else
      code = psg_parse_int((spelled.start_with?('0x') ? psg_slice(spelled, 2) : psg_slice(spelled, 1)), 16)
      if !(code >= 0)
        return 'the LEEF delimiter field does not declare a delimiter'
      end
      delimiter = psg_from_code_point(code)
    end
  end
  length = psg_len(text)
  seen = 0
  while (cursor < length)
    key = ''
    while (((cursor < length) && (psg_at(text, cursor) != '=')) && (psg_at(text, cursor) != delimiter))
      key += psg_at(text, cursor)
      cursor += 1
    end
    if (psg_at(text, cursor) != '=')
      return 'text of the LEEF extension is not part of any extracted attribute'
    end
    cursor += 1
    value = (psg_k_leef_header_fields.include?(key) ? nil : fields[psg_source_field_name(key)])
    if !value.is_a?(String)
      return 'an attribute of the LEEF extension is missing from the extracted fields'
    end
    if !psg_starts_with(text, value, cursor)
      return 'an extracted LEEF value is not the text of its attribute'
    end
    cursor += psg_len(value)
    seen += 1
    if (cursor == length)
      break
    end
    if (psg_at(text, cursor) != delimiter)
      return 'an extracted LEEF value ends before the text of its value does'
    end
    cursor += 1
    if (cursor == length)
      return 'text of the LEEF extension is not part of any extracted attribute'
    end
  end
  return ((fields.keys.length == (5 + seen)) ? :psg_null : 'an extracted field is not in the LEEF extension')
end

# src/grammar/readEvent.ts: malformedFamilyClaim
def psg_malformed_family_claim(settings, extraction)
  kind = message = start = text = claim = family = nil
  if ((settings['format'] != 'syslog_rfc3164') && (settings['format'] != 'syslog_rfc5424'))
    return ''
  end
  kind = psg_body_kind_of(extraction)
  if (!kind.nil? && (kind != 'raw'))
    return ''
  end
  message = extraction['fields']['message']
  if !message.is_a?(String)
    return ''
  end
  start = 0
  while ((start < psg_len(message)) && (((psg_at(message, start) == "\u{feff}") || (psg_at(message, start) == ' ')) || (psg_at(message, start) == "\u{9}")))
    start += 1
  end
  text = psg_slice(message, start)
  claim = psg_match_at(/\G(?:(?<family>(?:CEF|LEEF))(?:(?:[ \t]))*:(?:(?:[ \t]))*(?:[0-9]))/, text, 0)
  if claim.equal?(:psg_null)
    return ''
  end
  family = ((psg_group(claim, 'family') == 'LEEF') ? 'leef' : 'cef')
  return ((psg_extract_structured_family(text, family)['errors'].length > 0) ? psg_group(claim, 'family') : '')
end

# src/grammar/syslogHeader.ts: matchHeaderRule
def psg_match_header_rule(rule, text)
  match = captures = nil
  match = (psg_k_compiled_rules[rule].match(text) || :psg_null)
  if !psg_t(match)
    return :psg_null
  end
  captures = {}
  psg_k_syslog_header_rules[rule]['captures'].each do |name|
    captures[name] = psg_group(match, name)
  end
  return captures
end

# src/grammar/syslogHeader.ts: matchRfc3164Header
def psg_match_rfc3164_header(text)
  captures = pri = month = day = days = nil
  psg_k_syslog_header_alternatives['rfc3164'].each do |rule|
    captures = psg_match_header_rule(rule, text)
    if !psg_t(captures)
      next
    end
    if (((rule == 'rfc3164_tagged') && captures['pri'].nil?) && !psg_matches_header_token('STRUCTURED_BODY', captures['message']))
      next
    end
    pri = (captures['pri'].nil? ? nil : psg_num(captures['pri']))
    if (!pri.nil? && (pri > 191))
      return {'ok' => false, 'reason' => 'PRI_OUT_OF_RANGE'}
    end
    month = captures['month']
    day = psg_num(captures['day'])
    days = psg_k_syslog_header_semantics['bsdMonthDays'][month]
    if (((((!psg_t(days) || (day < 1)) || (day > days)) || (psg_num(captures['hour']) > 23)) || (psg_num(captures['minute']) > 59)) || (psg_num(captures['second']) > 59))
      return {'ok' => false, 'reason' => 'CALENDAR_INVALID'}
    end
    return {'ok' => true, 'rule' => rule}.merge!((pri.nil? ? {} : {'pri' => pri})).merge!({'timestamp' => (month + ' ' + psg_pad_start(psg_str(day), 2, ' ') + ' ' + psg_str(captures['hour']) + ':' + psg_str(captures['minute']) + ':' + psg_str(captures['second']))}).merge!((captures['hostname'].nil? ? {} : {'hostname' => captures['hostname']})).merge!((captures['tag'].nil? ? {} : {'tag' => captures['tag']})).merge!((captures['procid'].nil? ? {} : {'procid' => captures['procid']})).merge!({'message' => captures['message']})
  end
  return {'ok' => false, 'reason' => 'NO_MATCH'}
end

# src/grammar/syslogHeader.ts: matchRfc5424Header
def psg_match_rfc5424_header(text)
  captures = pri = nil
  captures = psg_match_header_rule('rfc5424', text)
  if !psg_t(captures)
    return {'ok' => false, 'reason' => 'NO_MATCH'}
  end
  pri = psg_num(captures['pri'])
  if (pri > 191)
    return {'ok' => false, 'reason' => 'PRI_OUT_OF_RANGE'}
  end
  if !psg_is_supported_rfc5424_version(captures['version'])
    return {'ok' => false, 'reason' => 'VERSION_UNSUPPORTED'}
  end
  return {'ok' => true, 'pri' => pri, 'version' => captures['version'], 'timestamp' => captures['timestamp'], 'hostname' => captures['hostname'], 'appname' => captures['appname'], 'procid' => captures['procid'], 'msgid' => captures['msgid'], 'rest' => captures['rest']}
end

# src/grammar/syslogHeader.ts: matchesHeaderToken
def psg_matches_header_token(token, text)
  return psg_k_compiled_tokens[token].match?(text)
end

# src/grammar/extractEvent.ts: mixedFamily
def psg_mixed_family(result, family)
  if (result['errors'].length == 0)
    psg_set_tag(result, 'mixedFamily', family)
  end
  return result
end

# src/grammar/sourceFieldNames.ts: needsRenaming
def psg_needs_renaming(value)
  record = nil
  if value.is_a?(Array)
    return psg_some(value, method(:psg_needs_renaming))
  end
  if (value.equal?(:psg_null) || !(psg_typeof(value) == 'object'))
    return false
  end
  record = value
  return psg_some(record.keys, lambda { |name| ((psg_source_field_name(name) != name) || psg_needs_renaming(record[name])) })
end

# src/grammar/sourceFieldNames.ts: originalFieldName
def psg_original_field_name(name)
  return (name.start_with?('parserstudio_key_') ? psg_slice(name, 17) : name)
end

# src/javaStacktrace.ts: parseJavaStacktrace
def psg_parse_java_stacktrace(text)
  lines = head = frames = causes = root = last = matched = nil
  if ((((!text.is_a?(String) || text.include?("\u{d}")) || text.include?("\u{a}\u{a}")) || !text.include?("\u{a}")) || (text.bytesize > 8192))
    return psg_error()
  end
  lines = psg_split(text, "\u{a}")
  if (((lines.length < 2) || (lines.length > 64)) || psg_some(lines, lambda { |line| ((psg_len(line) == 0) || (line.bytesize > 512)) }))
    return psg_error()
  end
  head = (/\A((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error))(?:: [^\n]{1,256})?\z/.match(lines[0]) || :psg_null)
  if !psg_t(head)
    return psg_error()
  end
  frames = 0
  causes = 0
  root = nil
  last = 'header'
  psg_slice(lines, 1).each do |line_2|
    if /\A[ \t]+at [A-Za-z_$][A-Za-z0-9_.$\/]*\((?:[A-Za-z0-9_.$\/\-]+\.java:[0-9]{1,5}|Unknown Source|Native Method)\)\z/.match?(line_2)
      frames += 1
      last = 'frame'
    else
      matched = (/\ACaused by: ((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error))(?:: [^\n]{1,256})?\z/.match(line_2) || :psg_null)
      if psg_t(matched)
        causes += 1
        if (causes > 4)
          return psg_error()
        end
        root = matched[1]
        last = 'cause'
      elsif ((/\A[ \t]*\.\.\. [1-9][0-9]{0,2} more\z/.match?(line_2) && (causes > 0)) && (last == 'frame'))
        last = 'more'
      else
        return psg_error()
      end
    end
  end
  if ((frames == 0) || (last == 'cause'))
    return psg_error()
  end
  return {'fields' => {'exception_class' => head[1], 'frame_count' => frames}.merge!((psg_t(root) ? {'cause_class' => root} : {})), 'errors' => []}
end

# src/structuredFamilies.ts: parseRfc3164Strict
def psg_parse_rfc3164_strict(input, choice, regexPattern = nil)
  header = tagged = fields = message = mode = body = result = nil
  header = psg_match_rfc3164_header(input)
  if !header['ok']
    return psg_failure_2(((header['reason'] == 'NO_MATCH') ? 'RFC3164 bounded BSD security header required' : 'RFC3164 PRI or calendar value is invalid'))
  end
  tagged = (header['rule'] == 'rfc3164_tagged')
  fields = {}.merge!((!header['pri'].nil? ? {'syslog_pri' => header['pri']} : {})).merge!({'syslog_timestamp' => header['timestamp'], 'syslog_time_policy' => 'YEAR_AND_ZONE_UNKNOWN'}).merge!((!header['hostname'].nil? ? {'syslog_hostname' => header['hostname']} : {})).merge!((tagged ? {'syslog_appname' => header['tag']}.merge!((psg_t(header['procid']) ? {'syslog_procid' => header['procid']} : {})) : {}))
  message = header['message']
  mode = ((choice == 'auto') ? psg_deterministic_body(message) : choice)
  if (!tagged && (mode == 'raw'))
    return psg_failure_2('Tagless RFC3164 requires an explicit structured security body')
  end
  body = psg_parsed_body(message, mode, regexPattern)
  if psg_t(body['errors'].length)
    return body
  end
  result = psg_with_body_kind({'fields' => {}.merge!(fields).merge!(body['fields']), 'errors' => []}, psg_body_kind_of(body))
  psg_set_tag(result, 'rfc3164Header', true)
  psg_set_tag(result, 'bodyText', message)
  return result
end

# src/rfc5424Subset.ts: parseRfc5424Subset
def psg_parse_rfc5424_subset(text)
  header = parsed = nil
  if (text.include?("\u{a}") || text.include?("\u{d}"))
    return {'ok' => false, 'error' => 'RFC5424 multi-line message unsupported'}
  end
  header = psg_match_rfc5424_header(text)
  if !header['ok']
    return {'ok' => false, 'error' => 'Unsupported RFC5424 version or header'}
  end
  if !psg_safe_timestamp(header['timestamp'])
    return {'ok' => false, 'error' => 'Unsupported RFC5424 timestamp'}
  end
  parsed = psg_scan_structured_data(header['rest'])
  if !psg_t(parsed)
    return {'ok' => false, 'error' => 'Unsupported RFC5424 structured data syntax'}
  end
  return {'ok' => true, 'fields' => {'syslog_pri' => header['pri'], 'syslog_version' => psg_num(header['version']), 'syslog_timestamp' => header['timestamp'], 'syslog_hostname' => header['hostname'], 'syslog_appname' => header['appname'], 'syslog_procid' => header['procid'], 'syslog_msgid' => header['msgid'], 'syslog_structured_data' => parsed['structured']}.merge!((psg_t(parsed['elements'].keys.length) ? {'syslog_sd' => parsed['elements']} : {})), 'message' => parsed['message']}
end

# src/grammar/kvBody.ts: parseStrictKeyValues
def psg_parse_strict_key_values(input)
  pairs = seen = listed = cursor = separator = match = key = quoted = value = nil
  pairs = []
  seen = {}
  listed = psg_is_delimited_pair_list(input)
  cursor = 0
  while (cursor < psg_len(input))
    if /\A(?:[ \t\n\r\f\x0b]*)\z/.match?(psg_slice(input, cursor))
      break
    end
    if (listed && (pairs.length > 0))
      separator = psg_match_at(/\G(?:(?<delimiter>[,;|]))/, input, cursor)
      if !psg_t(separator)
        return {'ok' => false, 'reason' => 'MALFORMED_PAIR'}
      end
      cursor = psg_match_end(separator)
    end
    match = (listed ? psg_match_at(/\G(?:(?:[ \t]*)(?<key>[A-Za-z_][A-Za-z0-9_.\-]{0,95})=(?:"(?<dq>[^"]*)"|'(?<sq>[^']*)'|(?<bare>[^ \t\n\r\f\x0b\x1c-\x1f"',;|=]+)))/, input, cursor) : psg_match_at(/\G(?:(?:[ \t]*)(?<key>[A-Za-z_][A-Za-z0-9_.\-]{0,95})=(?:"(?<dq>(?:\\[^\r\n]|[^"\\])*)"|'(?<sq>(?:\\[^\r\n]|[^'\\])*)'|(?<bare>(?:\\[^ \t\n\r\f\x0b\x1c-\x1f]|[^ \t\n\r\f\x0b\x1c-\x1f"'\\]|\\)+)))/, input, cursor))
    if (!psg_t(match) || (psg_match_end(match) <= cursor))
      return {'ok' => false, 'reason' => 'MALFORMED_PAIR'}
    end
    key = psg_source_field_name(psg_group(match, 'key'))
    if seen.key?(key)
      return {'ok' => false, 'reason' => 'DUPLICATE_KEY', 'key' => key}
    end
    if (pairs.length >= 100)
      return {'ok' => false, 'reason' => 'TOO_MANY_PAIRS'}
    end
    seen[key] = true
    quoted = (psg_null?(psg_t1 = psg_group(match, 'dq')) ? psg_group(match, 'sq') : psg_t1)
    value = (quoted.nil? ? (psg_null?(psg_t2 = psg_group(match, 'bare')) ? '' : psg_t2) : psg_unescape_kv_value(quoted))
    pairs.push([key, ((listed && !quoted.nil?) ? quoted : value)])
    cursor = psg_match_end(match)
  end
  return ((pairs.length > 0) ? {'ok' => true, 'pairs' => pairs} : {'ok' => false, 'reason' => 'NO_PAIRS'})
end

# src/structuredFamilies.ts: parsedBody
def psg_parsed_body(message, mode, regexPattern = nil)
  result = nil
  if (mode == 'raw')
    return {'fields' => {'message' => message}, 'errors' => []}
  end
  result = ((mode == 'json') ? psg_bounded_json_object(message) : ((mode == 'kv') ? psg_strict_key_values(message) : ((mode == 'regex') ? psg_regex_body(message, regexPattern) : psg_extract_structured_family(message, mode))))
  return (psg_t(result['errors'].length) ? result : psg_with_body_kind({'fields' => {'body' => result['fields']}, 'errors' => []}, mode))
end

# src/grammar/parseStatus.ts: positionalHeaderEnd
def psg_positional_header_end(raw)
  index = token = space = nil
  if !/\A<[0-9]{1,3}>[0-9]{1,3} /.match?(raw)
    return 0
  end
  index = 0
  token = 0
  while (token < 6)
    space = psg_index(raw, ' ', index)
    if (space < 0)
      return psg_len(raw)
    end
    index = (space + 1)
    token += 1
  end
  return psg_structured_data_end(raw, index)
end

# src/structuredFamilies.ts: priOnlyPrefix
def psg_pri_only_prefix(input)
  match = pri = v_end = rest = nil
  match = (/\A<([0-9]{1,3})>[ \t]*/.match(input) || :psg_null)
  if match.equal?(:psg_null)
    return :psg_null
  end
  pri = psg_num(match[1])
  if (pri > 191)
    return :psg_null
  end
  v_end = psg_len(match[0])
  rest = psg_slice(input, v_end)
  if rest.start_with?('CEF:')
    return {'pri' => pri, 'end' => v_end, 'family' => 'cef'}
  end
  if rest.start_with?('LEEF:')
    return {'pri' => pri, 'end' => v_end, 'family' => 'leef'}
  end
  return :psg_null
end

# src/grammar/readEvent.ts: readEvent
def psg_read_event(raw, settings)
  relay = reason = source = extraction = verdict = family = nil
  relay = psg_inspect_declared_forwarders(raw, settings['forwarder'])
  if (relay['status'] == 'ABSTAIN_UNSAFE')
    reason = ('The forwarded log cannot be safely unwrapped: ' + relay['reason'])
    return {'fields' => {}, 'errors' => [reason], 'status' => 'UNKNOWN', 'reasons' => [reason], 'lostKeys' => [], 'forwarderHops' => [], 'family' => '', 'textKept' => false}
  end
  source = ((relay['status'] == 'UNWRAPPED') ? relay['payload'] : raw)
  extraction = psg_extract_event(source, settings)
  verdict = psg_grade_extraction(source, settings, extraction)
  family = psg_get_tag(extraction, 'mixedFamily')
  return {'fields' => extraction['fields'], 'errors' => extraction['errors'], 'status' => verdict['status'], 'reasons' => verdict['reasons'], 'lostKeys' => psg_map(verdict['lostPairs'], lambda { |pair| pair['key'] }), 'forwarderHops' => relay['hops'], 'family' => (family.is_a?(String) ? family : ''), 'textKept' => (verdict['textKept'] == true)}
end

# src/grammar/parseStatus.ts: readRawPairs
def psg_read_raw_pairs(raw, split, bareGaps)
  pairs = length = index = gapStart = tokenStart = key = quote = cursor = rawValue = value = v_end = stop = value_2 = nil
  pairs = []
  length = psg_len(raw)
  index = psg_positional_header_end(raw)
  while (index < length)
    gapStart = index
    index = psg_match_end(psg_match_at(/\G(?:[ \t\n\x0b\f\r]*)/, raw, index))
    if (index >= length)
      break
    end
    tokenStart = ((index > gapStart) || (pairs.length == 0))
    key = (tokenStart ? psg_match_at(/\G(?:[A-Za-z_][A-Za-z0-9_.\-]{0,95}=)/, raw, index) : psg_match_at(/\G(?:[^ \t\n\x0b\f\r,;|="']+=)/, raw, index))
    if psg_t(key)
      if (((index > gapStart) && (pairs.length > 0)) && !psg_is_list_delimiter(psg_at(raw, (gapStart - 1))))
        bareGaps.push(index)
      end
      index += psg_len(key[0])
      quote = psg_at(raw, index)
      if ((quote == '"') || (quote == '\''))
        cursor = psg_closing_quote(raw, quote, (index + 1))
        if (cursor >= 0)
          rawValue = psg_slice(raw, (index + 1), cursor)
          value = (rawValue.include?('\\') ? psg_replace(rawValue, /\\(?m:.)/, true, lambda { |pair| psg_slice(pair, 1) }) : rawValue)
          pairs.push({'key' => psg_slice(key[0], 0, (-1)), 'value' => value, 'rawValue' => rawValue, 'quoted' => true})
          index = (cursor + 1)
          if (((index < length) && psg_is_list_delimiter(psg_at(raw, index))) && (!psg_match_at(/\G(?:[^ \t\n\x0b\f\r,;|="']+=)/, raw, (index + 1)).equal?(:psg_null) || psg_key_starts_at(raw, psg_match_end(psg_match_at(/\G(?:[ \t\n\x0b\f\r]*)/, raw, (index + 1))), length)))
            index += 1
          end
          next
        end
      end
      v_end = psg_match_end(psg_match_at(/\G(?:[^ \t\n\x0b\f\r]*)/, raw, index))
      stop = psg_unquoted_value_end(raw, index, v_end, split)
      value_2 = psg_slice(raw, index, stop)
      pairs.push({'key' => psg_slice(key[0], 0, (-1)), 'value' => value_2, 'rawValue' => value_2, 'quoted' => false})
      index = ((stop < v_end) ? (stop + 1) : v_end)
      next
    end
    index = psg_match_end(psg_match_at(/\G(?:[^ \t\n\x0b\f\r]*)/, raw, index))
  end
  return pairs
end

# src/structuredFamilies.ts: regexBody
def psg_regex_body(message, pattern = nil)
  return psg_x_portable_regex_fields(message, (psg_null?(psg_t1 = pattern) ? '' : psg_t1))
end

# src/grammar/sourceFieldNames.ts: renamed
def psg_renamed(value)
  record = out = nil
  if value.is_a?(Array)
    return psg_map(value, method(:psg_renamed))
  end
  if (value.equal?(:psg_null) || !(psg_typeof(value) == 'object'))
    return value
  end
  record = value
  out = {}
  record.keys.each do |name|
    out[psg_source_field_name(name)] = psg_renamed(record[name])
  end
  return out
end

# src/grammar/lossGuard.ts: rowUnaccounted
def psg_row_unaccounted(text, delimiter, cells, strip)
  cursor = index = cell = written = nil
  cursor = 0
  index = 0
  while (index < cells.length)
    if strip
      while ((psg_at(text, cursor) == ' ') || (psg_at(text, cursor) == "\u{9}"))
        cursor += 1
      end
    end
    cell = psg_at(cells, index)
    if cell.is_a?(String)
      written = ((psg_at(text, cursor) == '"') ? (('"' + psg_join(psg_split(cell, '"'), '""')) + '"') : cell)
      if !psg_starts_with(text, written, cursor)
        return (('CSV cell ' + psg_str((index + 1))) + ' is not the text of the row at its position')
      end
      cursor += psg_len(written)
    elsif !cell.equal?(:psg_null)
      return (('CSV cell ' + psg_str((index + 1))) + ' is not text')
    end
    if strip
      while ((psg_at(text, cursor) == ' ') || (psg_at(text, cursor) == "\u{9}"))
        cursor += 1
      end
    end
    if (index < (cells.length - 1))
      if (psg_at(text, cursor) != delimiter)
        return ('the row has no delimiter after CSV cell ' + psg_str((index + 1)))
      end
      cursor += 1
    end
    index += 1
  end
  return ((cursor == psg_len(text)) ? :psg_null : 'text after the last CSV cell is not part of any cell')
end

# src/rfc5424Subset.ts: safeParameterKey
def psg_safe_parameter_key(name)
  if ((/\A[A-Za-z_][A-Za-z0-9_\-]{0,63}\z/.match?(name) && !['__proto__', 'constructor', 'prototype'].include?(name)) && !name.start_with?('param_hex_'))
    return name
  end
  return ('param_hex_' + psg_join(psg_map(name.bytes, lambda { |byte| psg_pad_start(byte.to_s(16), 2, '0') }), ''))
end

# src/rfc5424Subset.ts: safeTimestamp
def psg_safe_timestamp(timestamp)
  match = year = month = day = hour = minute = second = offsetHour = offsetMinute = y = m = d = civil = leap = nil
  if (timestamp == '-')
    return true
  end
  match = (/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,6})?(?:Z|([+\-])([0-9]{2}):([0-9]{2}))\z/.match(timestamp) || :psg_null)
  if !psg_t(match)
    return false
  end
  _, year, month, day, hour, minute, second, _, offsetHour, offsetMinute, _ = match.to_a
  y = psg_num(year)
  m = psg_num(month)
  d = psg_num(day)
  if ((((((((m < 1) || (m > 12)) || (d < 1)) || (d > 31)) || (psg_num(hour) > 23)) || (psg_num(minute) > 59)) || (psg_num(second) > 59)) || (!offsetHour.nil? && ((psg_num(offsetHour) > 23) || (psg_num(offsetMinute) > 59))))
    return false
  end
  civil = ((y < 100) ? (1900 + y) : y)
  leap = (((psg_mod(civil, 4) == 0) && (psg_mod(civil, 100) != 0)) || (psg_mod(civil, 400) == 0))
  return (d <= psg_at([31, (leap ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31], (m - 1)))
end

# src/rfc5424Subset.ts: scanStructuredData
def psg_scan_structured_data(rest)
  pos = counted = bytes = bytesTo = ids = elements = readName = id = names = params = name = terminated = value = character = code = escaped = key = structured = trailer = nil
  if (rest == '-')
    return {'structured' => '-', 'message' => :psg_null, 'elements' => {}}
  end
  if rest.start_with?('- ')
    return {'structured' => '-', 'message' => psg_slice(rest, 2), 'elements' => {}}
  end
  if !rest.start_with?('[')
    return :psg_null
  end
  pos = 0
  counted = 0
  bytes = 0
  bytesTo = lambda { |v_end|
  unit = previous = paired = nil
  while ((counted < v_end) && (counted < psg_len(rest)))
    unit = psg_char_code_at(rest, counted)
    previous = ((counted > 0) ? psg_char_code_at(rest, (counted - 1)) : 0)
    paired = ((((unit >= 56320) && (unit <= 57343)) && (previous >= 55296)) && (previous <= 56319))
    bytes += ((unit < 128) ? 1 : ((unit < 2048) ? 2 : (paired ? 1 : 3)))
    counted += 1
  end
  return bytes
}
  ids = {}
  elements = {}
  readName = lambda {
  start = c = nil
  start = pos
  while (pos < psg_len(rest))
    c = psg_char_code_at(rest, pos)
    if (((c < 33) || (c > 126)) || [34, 61, 91, 92, 93].include?(c))
      break
    end
    pos += 1
  end
  return ((((pos - start) >= 1) && ((pos - start) <= 32)) ? psg_slice(rest, start, pos) : :psg_null)
}
  while (psg_at(rest, pos) == '[')
    pos += 1
    id = readName.call()
    if (!psg_t(id) || ids.key?(id))
      return :psg_null
    end
    ids[id] = true
    names = {}
    params = {}
    while (psg_at(rest, pos) == ' ')
      pos += 1
      name = readName.call()
      if (!psg_t(name) || names.key?(name))
        return :psg_null
      end
      names[name] = true
      if ((psg_at(rest, ((pos += 1) - 1)) != '=') || (psg_at(rest, ((pos += 1) - 1)) != '"'))
        return :psg_null
      end
      terminated = false
      value = ''
      while (pos < psg_len(rest))
        character = psg_at(rest, ((pos += 1) - 1))
        code = psg_char_code_at(character, 0)
        if (character == '"')
          terminated = true
          break
        end
        if (character == '\\')
          escaped = psg_at(rest, ((pos += 1) - 1))
          if (((escaped != ']') && (escaped != '"')) && (escaped != '\\'))
            return :psg_null
          end
          value += escaped
        else
          if (((character == ']') || (code < 32)) || (code == 127))
            return :psg_null
          end
          value += character
        end
        if (bytesTo.call(pos) > 1024)
          return :psg_null
        end
      end
      if !terminated
        return :psg_null
      end
      key = psg_safe_parameter_key(name)
      if params.key?(key)
        return :psg_null
      end
      params[key] = value
    end
    if (psg_at(rest, ((pos += 1) - 1)) != ']')
      return :psg_null
    end
    elements[('element_' + psg_str(ids.length))] = {'sd_id' => id, 'params' => params}
    if (bytesTo.call(pos) > 1024)
      return :psg_null
    end
  end
  structured = psg_slice(rest, 0, pos)
  if (!psg_t(structured) || (bytesTo.call(pos) > 1024))
    return :psg_null
  end
  trailer = psg_slice(rest, pos)
  if (trailer == '')
    return {'structured' => structured, 'message' => :psg_null, 'elements' => elements}
  end
  if !trailer.start_with?(' ')
    return :psg_null
  end
  return {'structured' => structured, 'message' => psg_slice(trailer, 1), 'elements' => elements}
end

# src/guided/declaredForwarder.ts: singleEnvelope
def psg_single_envelope(raw)
  parsed = parsed_2 = nil
  if /\A<[0-9]{1,3}>1 /.match?(raw)
    parsed = psg_parse_rfc5424_subset(raw)
    if ((!parsed['ok'] || !parsed['message'].is_a?(String)) || !psg_t(psg_len(parsed['message'])))
      return :psg_null
    end
    return {'host' => parsed['fields']['syslog_hostname'], 'timestamp' => parsed['fields']['syslog_timestamp'], 'format' => 'rfc5424', 'payload' => parsed['message']}
  end
  if !raw.start_with?('<')
    return :psg_null
  end
  parsed_2 = psg_extract_structured_family(raw, 'syslog_rfc3164', 'raw')
  if (psg_t(parsed_2['errors'].length) || !parsed_2['fields']['message'].is_a?(String))
    return :psg_null
  end
  return {'host' => parsed_2['fields']['syslog_hostname'], 'timestamp' => parsed_2['fields']['syslog_timestamp'], 'format' => 'rfc3164', 'payload' => parsed_2['fields']['message']}
end

# src/grammar/sourceFieldNames.ts: sourceFieldName
def psg_source_field_name(name)
  return ((psg_k_reserved.include?(name) || name.start_with?('parserstudio_key_')) ? ('parserstudio_key_' + name) : name)
end

# src/structuredFamilies.ts: splitEscaped
def psg_split_escaped(text, delimiter, splits)
  output = escaped = nil
  output = ['']
  escaped = false
  text.each_char do |char|
    if (output.length > splits)
      output[(output.length - 1)] += char
      next
    end
    if escaped
      output[(output.length - 1)] += (((char == delimiter) || (char == '\\')) ? char : ('\\' + char))
      escaped = false
    elsif (char == '\\')
      escaped = true
    elsif ((char == delimiter) && (output.length <= splits))
      output.push('')
    else
      output[(output.length - 1)] += char
    end
  end
  if escaped
    return :psg_null
  end
  return ((output.length == (splits + 1)) ? output : :psg_null)
end

# src/structuredFamilies.ts: strictKeyValues
def psg_strict_key_values(input)
  body = values = nil
  body = psg_parse_strict_key_values(input)
  if !body['ok']
    return psg_failure_2({'MALFORMED_PAIR' => 'Unsupported or malformed extension key=value segment', 'FORBIDDEN_KEY' => ('Unsafe field name: ' + psg_str(body['key'])), 'DUPLICATE_KEY' => psg_duplicate_field_message(psg_str(body['key'])), 'TOO_MANY_PAIRS' => 'KV field limit exceeded: maximum 100 keys per event', 'NO_PAIRS' => 'No extension fields parsed'}[body['reason']])
  end
  values = {}
  body['pairs'].each do |(key, value)|
    values[key] = value
  end
  return psg_with_body_kind({'fields' => values, 'errors' => []}, 'kv')
end

# src/grammar/parseStatus.ts: structuredDataEnd
def psg_structured_data_end(raw, start)
  after = v_end = index = cursor = quoted = ch = v_end_2 = nil
  after = lambda { |index_2| ((index_2 == psg_len(raw)) ? index_2 : ((psg_at(raw, index_2) == ' ') ? (index_2 + 1) : (-1))) }
  if (psg_at(raw, start) == '-')
    v_end = after.call((start + 1))
    return ((v_end < 0) ? start : v_end)
  end
  index = start
  while (psg_at(raw, index) == '[')
    cursor = (index + 1)
    quoted = false
    psg_t1 = true
    while true
      if psg_t1 then psg_t1 = false else cursor += 1 end
      break unless (cursor < psg_len(raw))
      ch = psg_at(raw, cursor)
      if (quoted && (ch == '\\'))
        cursor += 1
        next
      end
      if (ch == '"')
        quoted = !quoted
        next
      end
      if ((ch == ']') && !quoted)
        break
      end
    end
    if (cursor >= psg_len(raw))
      return start
    end
    index = (cursor + 1)
  end
  if (index == start)
    return start
  end
  v_end_2 = after.call(index)
  return ((v_end_2 < 0) ? start : v_end_2)
end

# src/grammar/extractEvent.ts: tokenizeCsvRow
def psg_tokenize_csv_row(raw, delimiter)
  out = stripUnquoted = token = from = state = i = c = nil
  if !psg_k_csv_delimiters.include?(delimiter)
    return :psg_null
  end
  out = []
  stripUnquoted = (delimiter != "\u{9}")
  token = ''
  from = 0
  state = 'start'
  i = 0
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else i += 1 end
    break unless (i < psg_len(raw))
    c = psg_at(raw, i)
    if (state == 'quoted')
      if (c == '"')
        token += psg_slice(raw, from, i)
        if (psg_at(raw, (i + 1)) == '"')
          token += '"'
          i += 1
          from = (i + 1)
        else
          state = 'afterQuote'
        end
      end
    elsif (state == 'afterQuote')
      if (c == delimiter)
        out.push(token)
        token = ''
        state = 'start'
      elsif (stripUnquoted && ((c == ' ') || (c == "\u{9}")))
        next
      else
        return :psg_null
      end
    elsif (c == delimiter)
      out.push(((state == 'start') ? :psg_null : (stripUnquoted ? psg_without_edge_blanks(psg_slice(raw, from, i)) : psg_slice(raw, from, i))))
      token = ''
      state = 'start'
    elsif (c == '"')
      if (state != 'start')
        return :psg_null
      end
      state = 'quoted'
      from = (i + 1)
    elsif (((state == 'start') && stripUnquoted) && ((c == ' ') || (c == "\u{9}")))
      next
    else
      if (state == 'start')
        from = i
      end
      state = 'plain'
    end
  end
  if (state == 'quoted')
    return :psg_null
  end
  out.push(((state == 'start') ? :psg_null : ((state == 'afterQuote') ? token : (stripUnquoted ? psg_without_edge_blanks(psg_slice(raw, from)) : psg_slice(raw, from)))))
  if ((out.length == 1) && out[0].equal?(:psg_null))
    return :psg_null
  end
  return out
end

# src/grammar/readEvent.ts: unaccountedText
def psg_unaccounted_text(raw, settings, extraction)
  kind = cells = message = text = body = fields = nil
  kind = psg_body_kind_of(extraction)
  if (kind == 'csv')
    cells = psg_map((psg_null?(psg_t1 = settings['csvColumns']) ? [] : psg_t1), lambda { |name| extraction['fields'][name] })
    if (extraction['fields'].keys.length != cells.length)
      return 'an extracted field is not a CSV column of the row'
    end
    return psg_csv_row_unaccounted(raw, (psg_null?(psg_t2 = settings['csvDelimiter']) ? ',' : psg_t2), cells)
  end
  if (((kind != 'json') && (kind != 'cef')) && (kind != 'leef'))
    return :psg_null
  end
  message = psg_get_tag(extraction, 'bodyText')
  text = (message.is_a?(String) ? message : raw)
  body = (message.is_a?(String) ? extraction['fields']['body'] : extraction['fields'])
  if ((body.equal?(:psg_null) || !(psg_typeof(body) == 'object')) || body.is_a?(Array))
    return 'the fields of the event body are not where the extractor reports them'
  end
  fields = body
  if (kind == 'json')
    return psg_json_text_unaccounted(text, fields)
  end
  return ((kind == 'cef') ? psg_cef_event_unaccounted(text, fields) : psg_leef_event_unaccounted(text, fields))
end

# src/grammar/kvBody.ts: unescapeKvValue
def psg_unescape_kv_value(raw)
  out = index = v_next = nil
  if !raw.include?('\\')
    return raw
  end
  out = ''
  index = 0
  while (index < psg_len(raw))
    v_next = psg_at(raw, (index + 1))
    if ((psg_at(raw, index) == '\\') && !v_next.nil?)
      out += (psg_k_unescaped.include?(v_next) ? v_next : ('\\' + v_next))
      index += 1
    else
      out += psg_at(raw, index)
    end
    index += 1
  end
  return out
end

# src/grammar/parseStatus.ts: unquotedValueEnd
def psg_unquoted_value_end(raw, from, v_end, split)
  query = at = ch = nil
  query = false
  at = from
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else at += 1 end
    break unless (at < v_end)
    ch = psg_at(raw, at)
    if (ch == '?')
      query = true
      next
    end
    if (ch == '&')
      if (((split && !query) && ((at + 1) < v_end)) && !psg_match_at(/\G(?:[^ \t\n\x0b\f\r,;|="']+=)/, raw, (at + 1)).equal?(:psg_null))
        return at
      end
      next
    end
    if !psg_is_list_delimiter(ch)
      next
    end
    if ((at + 1) < v_end)
      if (split && !psg_match_at(/\G(?:[^ \t\n\x0b\f\r,;|="']+=)/, raw, (at + 1)).equal?(:psg_null))
        return at
      end
    elsif psg_key_starts_at(raw, psg_match_end(psg_match_at(/\G(?:[ \t\n\x0b\f\r]*)/, raw, v_end)), psg_len(raw))
      return at
    end
  end
  return v_end
end

# src/guided/declaredForwarder.ts: validForwarderConfig
def psg_valid_forwarder_config(config = nil)
  return (!config || ((((((psg_integer?(config['maxHops']) && (config['maxHops'] >= 1)) && (config['maxHops'] <= 3)) && (config['relayHosts'].length >= 1)) && (config['relayHosts'].length <= 8)) && (psg_set(config['relayHosts']).length == config['relayHosts'].length)) && psg_every(config['relayHosts'], lambda { |host| /\A[A-Za-z0-9_][A-Za-z0-9_.\-]{0,254}\z/.match?(host) })))
end

# src/structuredFamilies.ts: withBodyKind
def psg_with_body_kind(extraction, kind = nil)
  if (!kind.nil? && (extraction['errors'].length == 0))
    psg_set_tag(extraction, 'bodyKind', kind)
  end
  return extraction
end

# src/grammar/sourceFieldNames.ts: withSourceFieldNames
def psg_with_source_field_names(value)
  return (psg_needs_renaming(value) ? psg_renamed(value) : value)
end

# src/grammar/extractEvent.ts: withoutEdgeBlanks
def psg_without_edge_blanks(token)
  start = v_end = nil
  start = 0
  v_end = psg_len(token)
  while ((start < v_end) && ((psg_at(token, start) == ' ') || (psg_at(token, start) == "\u{9}")))
    start += 1
  end
  while ((v_end > start) && ((psg_at(token, (v_end - 1)) == ' ') || (psg_at(token, (v_end - 1)) == "\u{9}")))
    v_end -= 1
  end
  return (((start == 0) && (v_end == psg_len(token))) ? token : psg_slice(token, start, v_end))
end
