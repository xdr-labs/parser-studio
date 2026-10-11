/* Browser-only structural subset of RFC5424, CEF and LEEF.
   Does not execute Ruby or imply native Fluentd target compatibility. */
export type StructuredFamily = 'syslog_rfc5424' | 'cef' | 'leef';
export interface StructuredExtraction {
  fields: Record<string, unknown>;
  errors: string[];
}
const failure = (message: string): StructuredExtraction => ({ fields: {}, errors: [message] });

export function detectStructuredFamily(input: string): StructuredFamily | null {
  if (/^CEF:\d+\|/.test(input)) return 'cef';
  if (/^LEEF:(?:1\.0|2\.0)\|/.test(input)) return 'leef';
  if (/^<\d{1,3}>[1-9]\d? \S+ \S+ \S+ /.test(input)) return 'syslog_rfc5424';
  return null;
}

function splitEscaped(text: string, delimiter: string, splits: number): string[] | null {
  const output = [''];
  let escaped = false;
  for (const char of text) {
    if (escaped) {
      output[output.length - 1] += char === delimiter || char === '\\' ? char : '\\' + char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === delimiter && output.length <= splits) {
      output.push('');
    } else {
      output[output.length - 1] += char;
    }
  }
  if (escaped) output[output.length - 1] += '\\';
  return output.length === splits + 1 ? output : null;
}

function strictKeyValues(input: string): StructuredExtraction {
  const values: Record<string, unknown> = Object.create(null);
  const pattern = /[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|((?:\\.|[^\s])+))/y;
  let cursor = 0;
  while (cursor < input.length) {
    if (!input.slice(cursor).trim()) break;
    pattern.lastIndex = cursor;
    const token = pattern.exec(input);
    if (!token || token.index !== cursor) return failure('Unsupported or malformed extension key=value segment');
    const key = token[1];
    if (Object.prototype.hasOwnProperty.call(values, key)) return failure('Duplicate extension field');
    values[key] = (token[2] ?? token[3] ?? token[4] ?? '').replace(/\\(.)/gs, '$1');
    cursor = pattern.lastIndex;
  }
  if (!Object.keys(values).length) return failure('No extension fields parsed');
  return { fields: values, errors: [] };
}

export function extractStructuredFamily(input: string, format: StructuredFamily): StructuredExtraction {
  if (input.includes('\n') || input.includes('\r')) return failure('Only one logical record per physical line is supported for pairing.');
  if (format === 'syslog_rfc5424') {
    const match = /^<(\d{1,3})>([1-9]\d?) (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[[^\]\n]{1,1024}\])(?: ([^\n]*))?$/.exec(input);
    if (!match || Number(match[1]) > 191) return failure('Only bounded single-record RFC5424 headers are supported');
    return { fields: {
      syslog_pri: Number(match[1]), syslog_version: Number(match[2]),
      syslog_timestamp: match[3], syslog_hostname: match[4],
      syslog_appname: match[5], syslog_procid: match[6],
      syslog_msgid: match[7], syslog_structured_data: match[8],
      ...(match[9] ? { message: match[9] } : {}),
    }, errors: [] };
  }
  if (format === 'cef') {
    const match = /^CEF:(\d+)\|(.*)$/.exec(input);
    if (!match) return failure('Only standalone CEF header events are supported');
    const parts = splitEscaped(match[2], '|', 6);
    if (!parts) return failure('CEF requires six header fields and an extension slot');
    const record: Record<string, unknown> = {
      cef_version: match[1], cef_device_vendor: parts[0],
      cef_device_product: parts[1], cef_device_version: parts[2],
      cef_signature_id: parts[3], cef_name: parts[4], cef_severity: parts[5],
    };
    if (parts[6].trim()) {
      const extension = strictKeyValues(parts[6]);
      if (extension.errors.length) return extension;
      for (const [key, value] of Object.entries(extension.fields)) {
        if (Object.prototype.hasOwnProperty.call(record, key)) return failure('Extension overrides a reserved CEF header field');
        record[key] = value;
      }
    }
    return { fields: record, errors: [] };
  }
  const match = /^LEEF:(1\.0|2\.0)\|(.*)$/.exec(input);
  if (!match) return failure('Only standalone LEEF 1.0 or 2.0 events are supported');
  const isV2 = match[1] === '2.0';
  const parts = splitEscaped(match[2], '|', isV2 ? 5 : 4);
  if (!parts) return failure('LEEF header or declared delimiter is incomplete');
  const delimiter = isV2 ? (parts[4] === '0x09' || parts[4] === '0x9' ? '\t' : parts[4]) : '\t';
  if (delimiter.length !== 1) return failure('LEEF 2.0 requires a one-character delimiter');
  const record: Record<string, unknown> = {
    leef_version: match[1], leef_vendor: parts[0], leef_product: parts[1],
    leef_product_version: parts[2], leef_event_id: parts[3],
  };
  if (parts[parts.length - 1]) {
    for (const part of parts[parts.length - 1].split(delimiter)) {
      const location = part.indexOf('=');
      const key = part.slice(0, location);
      if (location < 0 || !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key) ||
          Object.prototype.hasOwnProperty.call(record, key)) return failure('Unsupported or duplicate LEEF extension token');
      record[key] = part.slice(location + 1);
    }
  }
  return { fields: record, errors: [] };
}
