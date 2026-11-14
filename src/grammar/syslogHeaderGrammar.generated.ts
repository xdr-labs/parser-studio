// GENERATED FILE - DO NOT EDIT.
// Source: contracts/syslog-header-grammar.v1.json (revision 3); regenerate with
//   node scripts/grammar/generate-grammar.mjs --write
// CI runs the generator with --verify, so a hand edit of this file fails the gate.
export const GRAMMAR_CONTRACT_SHA256 = "3d561d4bb7c17f4dc19528b667a35bbf0efff4be2e019ec4d1bc63a42a74b755";
export const GRAMMAR_CONTRACT_REVISION = 3;
export interface CompiledHeaderRule { readonly source: string; readonly captures: readonly string[] }
export const SYSLOG_HEADER_RULES = {
  "rfc3164_tagged": {
    "source": "^<(?<pri>[0-9]{1,3})>(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)$",
    "captures": [
      "pri",
      "month",
      "day",
      "hour",
      "minute",
      "second",
      "hostname",
      "tag",
      "procid",
      "message"
    ]
  },
  "rfc3164_tagless": {
    "source": "^(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<message>[^\\r\\n]+)$",
    "captures": [
      "pri",
      "month",
      "day",
      "hour",
      "minute",
      "second",
      "hostname",
      "message"
    ]
  },
  "rfc3164_hostless": {
    "source": "^(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)$",
    "captures": [
      "pri",
      "month",
      "day",
      "hour",
      "minute",
      "second",
      "message"
    ]
  },
  "rfc5424": {
    "source": "^<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?<timestamp>[!-~]{1,64})[ ](?<hostname>[!-~]{1,255})[ ](?<appname>[!-~]{1,48})[ ](?<procid>[!-~]{1,128})[ ](?<msgid>[!-~]{1,32})[ ](?<rest>[^\\r\\n]+)$",
    "captures": [
      "pri",
      "version",
      "timestamp",
      "hostname",
      "appname",
      "procid",
      "msgid",
      "rest"
    ]
  }
} as const satisfies Record<string, CompiledHeaderRule>;
/** Unanchored patterns matched at a position; compile them with the sticky flag. */
export const GRAMMAR_FRAGMENTS = {
  "kv_pair": {
    "source": "(?:[ \\t]*)(?<key>[A-Za-z_][A-Za-z0-9_.-]{0,95})=(?:\"(?<dq>(?:\\\\[^\\r\\n]|[^\"\\\\])*)\"|'(?<sq>(?:\\\\[^\\r\\n]|[^'\\\\])*)'|(?<bare>(?:\\\\[^\\n\\r\\f\\v\\x1c-\\x1f]|[^ \\t\\n\\r\\f\\v\\x1c-\\x1f\"'\\\\])+))",
    "captures": [
      "key",
      "dq",
      "sq",
      "bare"
    ]
  },
  "rfc5424_version_head": {
    "source": "<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?:-[ ]|(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T))",
    "captures": [
      "pri",
      "version"
    ]
  }
} as const satisfies Record<string, CompiledHeaderRule>;
export const SYSLOG_HEADER_TOKENS = {
  "PRI": "[0-9]{1,3}",
  "BSD_MONTH": "[A-Z][a-z]{2}",
  "BSD_DAY": "[0-9]{1,2}",
  "CLOCK2": "[0-9]{2}",
  "BSD_HOSTNAME": "(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~]",
  "TAG": "[A-Za-z_][A-Za-z0-9_.-]{0,95}",
  "PROCID_NUM": "[0-9]{1,8}",
  "REST": "[^\\r\\n]+",
  "STRUCTURED_BODY": "(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*",
  "RFC5424_VERSION": "[1-9][0-9]{0,2}",
  "RFC5424_TIMESTAMP": "[!-~]{1,64}",
  "RFC5424_HOSTNAME": "[!-~]{1,255}",
  "RFC5424_APPNAME": "[!-~]{1,48}",
  "RFC5424_PROCID": "[!-~]{1,128}",
  "RFC5424_MSGID": "[!-~]{1,32}",
  "KV_GAP": "[ \\t]*",
  "KV_KEY": "[A-Za-z_][A-Za-z0-9_.-]{0,95}",
  "KV_DQ": "(?:\\\\[^\\r\\n]|[^\"\\\\])*",
  "KV_SQ": "(?:\\\\[^\\r\\n]|[^'\\\\])*",
  "KV_BARE": "(?:\\\\[^\\n\\r\\f\\v\\x1c-\\x1f]|[^ \\t\\n\\r\\f\\v\\x1c-\\x1f\"'\\\\])+",
  "KV_TRAILING": "[ \\t\\n\\r\\f\\v]*",
  "RFC3339_DATE_PREFIX": "[0-9]{4}-[0-9]{2}-[0-9]{2}T"
} as const;
export const SYSLOG_HEADER_ALTERNATIVES = {
  "rfc3164": [
    "rfc3164_tagged",
    "rfc3164_tagless",
    "rfc3164_hostless"
  ]
} as const;
export const SYSLOG_HEADER_SEMANTICS = {
  "priMax": 191,
  "bsdMonthDays": {
    "Jan": 31,
    "Feb": 29,
    "Mar": 31,
    "Apr": 30,
    "May": 31,
    "Jun": 30,
    "Jul": 31,
    "Aug": 31,
    "Sep": 30,
    "Oct": 31,
    "Nov": 30,
    "Dec": 31
  },
  "rfc5424SupportedVersions": [
    "1"
  ],
  "kvMaxPairs": 100,
  "kvForbiddenKeys": [
    "__proto__",
    "constructor",
    "prototype"
  ],
  "kvUnescapedAfterBackslash": [
    "\\",
    "\"",
    "'",
    "="
  ],
  "kvAsciiWhitespace": [
    " ",
    "\t",
    "\n",
    "\r",
    "\f",
    "\u000b"
  ]
} as const;
export type SyslogHeaderRuleName = keyof typeof SYSLOG_HEADER_RULES;
