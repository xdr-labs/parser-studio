// GENERATED FILE - DO NOT EDIT.
// Source: contracts/syslog-header-grammar.v1.json (revision 2); regenerate with
//   node scripts/grammar/generate-grammar.mjs --write
// CI runs the generator with --verify, so a hand edit of this file fails the gate.
export const GRAMMAR_CONTRACT_SHA256 = "be31ffb74393c162a84285d6b3c75aaa2a6e2b4443754b2e3964a80cd1bf20fb";
/** Template placeholder -> Ruby source text (Ruby 2.4 compatible). */
export const RUBY_GRAMMAR_PLACEHOLDERS: Readonly<Record<string, string>> = {
  "__PS_GRAMMAR_RX_RFC3164_TAGGED__": "\\A<(?<pri>[0-9]{1,3})>(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_RX_RFC3164_TAGLESS__": "\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<message>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_RX_RFC3164_HOSTLESS__": "\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)\\z",
  "__PS_GRAMMAR_RX_RFC5424__": "\\A<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?<timestamp>[!-~]{1,64})[ ](?<hostname>[!-~]{1,255})[ ](?<appname>[!-~]{1,48})[ ](?<procid>[!-~]{1,128})[ ](?<msgid>[!-~]{1,32})[ ](?<rest>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_FRAGMENT_KV_PAIR__": "\\G(?:[ \\t]*)(?<key>[A-Za-z_][A-Za-z0-9_.-]{0,95})=(?:\"(?<dq>(?:\\\\[^\\r\\n]|[^\"\\\\])*)\"|'(?<sq>(?:\\\\[^\\r\\n]|[^'\\\\])*)'|(?<bare>(?:\\\\[^\\r\\n]|[^ \\t\\n\\r\\f\\v\"'\\\\])+))",
  "__PS_GRAMMAR_KV_MAX_PAIRS__": "100",
  "__PS_GRAMMAR_KV_UNESCAPED__": "['\\\\', '\"', '\\'', '=']",
  "__PS_GRAMMAR_TOKEN_PRI__": "[0-9]{1,3}",
  "__PS_GRAMMAR_TOKEN_BSD_MONTH__": "[A-Z][a-z]{2}",
  "__PS_GRAMMAR_TOKEN_BSD_DAY__": "[0-9]{1,2}",
  "__PS_GRAMMAR_TOKEN_CLOCK2__": "[0-9]{2}",
  "__PS_GRAMMAR_TOKEN_BSD_HOSTNAME__": "(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~]",
  "__PS_GRAMMAR_TOKEN_TAG__": "[A-Za-z_][A-Za-z0-9_.-]{0,95}",
  "__PS_GRAMMAR_TOKEN_PROCID_NUM__": "[0-9]{1,8}",
  "__PS_GRAMMAR_TOKEN_REST__": "[^\\r\\n]+",
  "__PS_GRAMMAR_TOKEN_STRUCTURED_BODY__": "(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*",
  "__PS_GRAMMAR_TOKEN_RFC5424_VERSION__": "[1-9][0-9]{0,2}",
  "__PS_GRAMMAR_TOKEN_RFC5424_TIMESTAMP__": "[!-~]{1,64}",
  "__PS_GRAMMAR_TOKEN_RFC5424_HOSTNAME__": "[!-~]{1,255}",
  "__PS_GRAMMAR_TOKEN_RFC5424_APPNAME__": "[!-~]{1,48}",
  "__PS_GRAMMAR_TOKEN_RFC5424_PROCID__": "[!-~]{1,128}",
  "__PS_GRAMMAR_TOKEN_RFC5424_MSGID__": "[!-~]{1,32}",
  "__PS_GRAMMAR_TOKEN_KV_GAP__": "[ \\t]*",
  "__PS_GRAMMAR_TOKEN_KV_KEY__": "[A-Za-z_][A-Za-z0-9_.-]{0,95}",
  "__PS_GRAMMAR_TOKEN_KV_DQ__": "(?:\\\\[^\\r\\n]|[^\"\\\\])*",
  "__PS_GRAMMAR_TOKEN_KV_SQ__": "(?:\\\\[^\\r\\n]|[^'\\\\])*",
  "__PS_GRAMMAR_TOKEN_KV_BARE__": "(?:\\\\[^\\r\\n]|[^ \\t\\n\\r\\f\\v\"'\\\\])+",
  "__PS_GRAMMAR_TOKEN_KV_TRAILING__": "[ \\t\\n\\r\\f\\v]*",
  "__PS_GRAMMAR_RFC3164_ALTERNATIVES__": "[['rfc3164_tagged', /\\A<(?<pri>[0-9]{1,3})>(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)\\z/], ['rfc3164_tagless', /\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~])[ ]+(?<message>[^\\r\\n]+)\\z/], ['rfc3164_hostless', /\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)\\z/]]",
  "__PS_GRAMMAR_PRI_MAX__": "191",
  "__PS_GRAMMAR_BSD_MONTH_DAYS__": "{'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}",
  "__PS_GRAMMAR_RFC5424_VERSIONS__": "['1']"
};
