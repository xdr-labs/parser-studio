# GENERATED FILE - DO NOT EDIT.
# Source: contracts/syslog-header-grammar.v1.json (revision 6); regenerate with
#   node scripts/grammar/generate-grammar.mjs --write
# CI runs the generator with --verify, so a hand edit of this file fails the gate.
# Syslog header grammar for the Multi-Pass engine, generated from the shared grammar contract.
GRAMMAR_CONTRACT_SHA256 = "8ba80890032304c52cd927066ea0d92cd476a39832e359df397298b4c26f8247"
TOKENS = {
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
  "RFC3339_DATE_PREFIX": "[0-9]{4}-[0-9]{2}-[0-9]{2}T",
  "FAMILY_NAME": "(?:CEF|LEEF)",
  "ASCII_DIGIT": "[0-9]",
  "CEF_KEY": "[A-Za-z_][A-Za-z0-9_.-]{0,127}",
  "LEEF_KEY": "[A-Za-z_][A-Za-z0-9_.-]*",
  "CEF_WS": "[ \\t]",
  "CEF_WS_RUN": "[ \\t]+",
  "CEF_NOT_WS": "[^ \\t]",
  "CEF_ESCAPE": "\\\\(?:[^\\\\]|\\\\)",
  "CEF_PLAIN": "[^\\\\ \\t]",
  "LEEF_DELIMITER_LITERAL": "[\\t!-<>-\\[\\]-~]",
  "LEEF_HEX_DIGITS": "[0-9A-Fa-f]{1,4}"
}
RULES = {
  "rfc3164_tagged": {
    "source": "\\A<(?P<pri>[0-9]{1,3})>(?P<month>[A-Z][a-z]{2})[ ]+(?P<day>[0-9]{1,2})[ ]+(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})[ ]+(?P<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?P<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?P<procid>[0-9]{1,8})\\])?:[ ]+(?P<message>[^\\r\\n]+)\\Z",
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
    "source": "\\A(?:<(?P<pri>[0-9]{1,3})>)?(?P<month>[A-Z][a-z]{2})[ ]+(?P<day>[0-9]{1,2})[ ]+(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})[ ]+(?P<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?P<message>[^\\r\\n]+)\\Z",
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
    "source": "\\A(?:<(?P<pri>[0-9]{1,3})>)?(?P<month>[A-Z][a-z]{2})[ ]+(?P<day>[0-9]{1,2})[ ]+(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})[ ]+(?P<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)\\Z",
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
    "source": "\\A<(?P<pri>[0-9]{1,3})>(?P<version>[1-9][0-9]{0,2})[ ](?P<timestamp>[!-~]{1,64})[ ](?P<hostname>[!-~]{1,255})[ ](?P<appname>[!-~]{1,48})[ ](?P<procid>[!-~]{1,128})[ ](?P<msgid>[!-~]{1,32})[ ](?P<rest>[^\\r\\n]+)\\Z",
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
}
FRAGMENTS = {
  "kv_pair": {
    "source": "(?:[ \\t]*)(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,95})=(?:\"(?P<dq>(?:\\\\[^\\r\\n]|[^\"\\\\])*)\"|'(?P<sq>(?:\\\\[^\\r\\n]|[^'\\\\])*)'|(?P<bare>(?:\\\\[^\\n\\r\\f\\v\\x1c-\\x1f]|[^ \\t\\n\\r\\f\\v\\x1c-\\x1f\"'\\\\])+))",
    "captures": [
      "key",
      "dq",
      "sq",
      "bare"
    ]
  },
  "rfc5424_version_head": {
    "source": "<(?P<pri>[0-9]{1,3})>(?P<version>[1-9][0-9]{0,2})[ ](?:-[ ]|(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T))",
    "captures": [
      "pri",
      "version"
    ]
  },
  "structured_family_claim": {
    "source": "(?P<family>(?:CEF|LEEF)):(?:[0-9])",
    "captures": [
      "family"
    ]
  },
  "cef_pair": {
    "source": "(?:(?:[ \\t]))*(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,127})=(?P<value>(?:(?:(?:\\\\(?:[^\\\\]|\\\\))|(?:[^\\\\ \\t])|(?:[ \\t]+)(?=(?:[^ \\t]))(?!(?:[A-Za-z_][A-Za-z0-9_.-]{0,127})=)|(?:[ \\t]+)(?=(?:[ \\t])(?:[A-Za-z_][A-Za-z0-9_.-]{0,127})=)))*)(?:(?:(?:[ \\t]))*\\Z|(?:[ \\t])(?=(?:[A-Za-z_][A-Za-z0-9_.-]{0,127})=))",
    "captures": [
      "key",
      "value"
    ]
  },
  "leef_delimiter": {
    "source": "(?:(?P<literal>[\\t!-<>-\\[\\]-~])|(?:0x|x)(?P<hex>[0-9A-Fa-f]{1,4}))\\Z",
    "captures": [
      "literal",
      "hex"
    ]
  },
  "leef_attribute": {
    "source": "(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=",
    "captures": [
      "key"
    ]
  }
}
ALTERNATIVES = {
  "rfc3164": [
    "rfc3164_tagged",
    "rfc3164_tagless",
    "rfc3164_hostless"
  ]
}
SEMANTICS = {
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
  ],
  "cefSupportedVersions": [
    "0"
  ],
  "cefMaxExtensionFields": 1024,
  "cefExtensionEscapes": {
    "n": "\n",
    "r": "\r",
    "=": "=",
    "\\": "\\"
  },
  "leefSupportedVersions": [
    "1.0",
    "2.0"
  ],
  "leefDelimiterFieldVersions": [
    "2.0"
  ],
  "leefDefaultDelimiter": "\t",
  "leefHeaderFields": 4,
  "leefDelimiterExtraCodePoints": [
    166
  ]
}
PRI_MAX = SEMANTICS['priMax']
BSD_MONTH_DAYS = SEMANTICS['bsdMonthDays']
RFC5424_SUPPORTED_VERSIONS = frozenset(SEMANTICS['rfc5424SupportedVersions'])
# White space for key=value scanning is ASCII only; str.isspace() would also split at NBSP and U+2028.
KV_ASCII_WHITESPACE = frozenset(SEMANTICS['kvAsciiWhitespace'])
