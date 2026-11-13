// GENERATED FILE - DO NOT EDIT.
// Source: contracts/syslog-header-grammar.v1.json (revision 1); regenerate with
//   node scripts/grammar/generate-grammar.mjs --write
// CI runs the generator with --verify, so a hand edit of this file fails the gate.
export const GRAMMAR_CONTRACT_SHA256 = "85ea7dbf726b22c1bbe2653fd726e825df1a1223f9eda1893c583d294fab0ac7";
/** Template placeholder -> Ruby source text (Ruby 2.4 compatible). */
export const RUBY_GRAMMAR_PLACEHOLDERS: Readonly<Record<string, string>> = {
  "__PS_GRAMMAR_RX_RFC3164_TAGGED__": "\\A<(?<pri>[0-9]{1,3})>(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{1,255})[ ]+(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_RX_RFC3164_TAGLESS__": "\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{1,255})[ ]+(?<message>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_RX_RFC3164_HOSTLESS__": "\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)\\z",
  "__PS_GRAMMAR_RX_RFC5424__": "\\A<(?<pri>[0-9]{1,3})>(?<version>[1-9][0-9]{0,2})[ ](?<timestamp>[!-~]{1,64})[ ](?<hostname>[!-~]{1,255})[ ](?<appname>[!-~]{1,48})[ ](?<procid>[!-~]{1,128})[ ](?<msgid>[!-~]{1,32})[ ](?<rest>[^\\r\\n]+)\\z",
  "__PS_GRAMMAR_RFC3164_ALTERNATIVES__": "[['rfc3164_tagged', /\\A<(?<pri>[0-9]{1,3})>(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{1,255})[ ]+(?<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\\[(?<procid>[0-9]{1,8})\\])?:[ ]+(?<message>[^\\r\\n]+)\\z/], ['rfc3164_tagless', /\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<hostname>(?!\\{|CEF:|LEEF:)[!-<>-~]{1,255})[ ]+(?<message>[^\\r\\n]+)\\z/], ['rfc3164_hostless', /\\A(?:<(?<pri>[0-9]{1,3})>)?(?<month>[A-Z][a-z]{2})[ ]+(?<day>[0-9]{1,2})[ ]+(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})[ ]+(?<message>(?:\\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=)[^\\r\\n]*)\\z/]]",
  "__PS_GRAMMAR_PRI_MAX__": "191",
  "__PS_GRAMMAR_BSD_MONTH_DAYS__": "{'Jan'=>31,'Feb'=>29,'Mar'=>31,'Apr'=>30,'May'=>31,'Jun'=>30,'Jul'=>31,'Aug'=>31,'Sep'=>30,'Oct'=>31,'Nov'=>30,'Dec'=>31}",
  "__PS_GRAMMAR_RFC5424_VERSIONS__": "['1']"
};
