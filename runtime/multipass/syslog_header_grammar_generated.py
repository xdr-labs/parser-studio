# GENERATED FILE - DO NOT EDIT.
# Source: contracts/syslog-header-grammar.v1.json (revision 1); regenerate with
#   node scripts/grammar/generate-grammar.mjs --write
# CI runs the generator with --verify, so a hand edit of this file fails the gate.
# Syslog header grammar for the Multi-Pass engine, generated from the shared grammar contract.
GRAMMAR_CONTRACT_SHA256 = "7d666ef2de165dbd6f1a4e327638327ae982d049c8b2a0fc27f62777c69ff03d"
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
  "RFC5424_MSGID": "[!-~]{1,32}"
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
  ]
}
PRI_MAX = SEMANTICS['priMax']
BSD_MONTH_DAYS = SEMANTICS['bsdMonthDays']
RFC5424_SUPPORTED_VERSIONS = frozenset(SEMANTICS['rfc5424SupportedVersions'])
