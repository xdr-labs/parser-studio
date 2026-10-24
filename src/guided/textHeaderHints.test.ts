import {describe,it,expect} from 'vitest';
import {inferTextHeaderHints} from './textHeaderHints';
import {buildPromptSourceEvidence} from './chatGptSourceEvidence';

const proxy=[
 '[10.30 16:49:06] chrome.exe - private-backend.example:5070 open through proxy private-backend.example:5070 HTTPS',
 '[07.26 13:31:09] firefox.exe *64 - secret-target.example:80 close, 0 bytes sent, 0 bytes received',
].join('\n');
const hdfs=[
 '081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_123 terminating',
 '081109 204132 26 WARN dfs.FSNamesystem: Received block blk_456 of size 67108864 from /192.0.2.12',
].join('\n');

describe('bounded, value-free irregular source hints',()=>{
 it('describes syntax without reproducing original hostnames or log values',()=>{
  const h=inferTextHeaderHints(proxy);
  expect(h).toMatchObject({
   contract:'parser-studio.text-header-hints.v0.1',inspectedRecords:2,
   matchedHeaderRecords:2,messageSemanticsVerified:false,
   dateYearOrTimezoneInferred:false,nativeParserVerified:false,
  });
  expect(h?.patterns).toEqual([{shape:'BRACKET_MONTH_DAY_PROCESS_TARGET',records:2,
   availableUnverifiedNames:['month_day_text','clock_text','application','message']}]);
  const onlyEvidence=buildPromptSourceEvidence(proxy).text;
  expect(onlyEvidence).toContain('BRACKET_MONTH_DAY_PROCESS_TARGET');
  expect(onlyEvidence).toContain('distinct holdout');
  expect(onlyEvidence).not.toContain('private-backend.example');
  expect(onlyEvidence).not.toContain('secret-target.example');
  expect(onlyEvidence).not.toContain('chrome.exe');
 });
 it('identifies six-digit textual header while refusing semantic guesses',()=>{
  const evidence=buildPromptSourceEvidence(hdfs).text;
  expect(evidence).toContain('SIX_DIGIT_DATE_TIME_SEVERITY_COMPONENT');
  expect(evidence).toContain('Do not guess');
  expect(evidence).toContain('REVIEW_REQUIRED');
  expect(evidence).not.toContain('blk_123');
  expect(evidence).not.toContain('192.0.2.12');
 });
 it('recognizes valid Logcat threadtime without claiming a complete event meaning',()=>{
  const source=[
   '03-17 16:13:38.811  1702  2395 D WindowManager: token=PRIVATE_EXAMPLE',
   '03-17 16:14:38.819  1702  8671 W ActivityManager: Unable to open',
  ].join('\n');
  const hints=inferTextHeaderHints(source);
  expect(hints?.patterns).toEqual([{
   shape:'ANDROID_LOGCAT_THREADTIME',records:2,
   availableUnverifiedNames:['month_day_text','clock_text','pid','tid','priority','tag','message'],
  }]);
  expect(hints?.dateYearOrTimezoneInferred).toBe(false);
  expect(hints?.messageSemanticsVerified).toBe(false);
  const prePrompt=buildPromptSourceEvidence(source).text;
  expect(prePrompt).toContain('ANDROID_LOGCAT_THREADTIME');
  expect(prePrompt).not.toContain('PRIVATE_EXAMPLE');
  expect(inferTextHeaderHints(
    '13-35 25:61:99.819  1702  8671 W ActivityManager: Invalid time')).toBeNull();
 });
 it('never turns arbitrary prose into a supported recipe grammar',()=>{
  expect(inferTextHeaderHints('Failed password for root from 203.0.113.2')).toBeNull();
  expect(inferTextHeaderHints('[13.77 25:66:99] strange.exe - unknown')).toBeNull();
  const evidence=buildPromptSourceEvidence('Failed password for root from 203.0.113.2').text;
  expect(evidence).not.toContain('BRACKET_MONTH_DAY_PROCESS_TARGET');
 });
 it('source with different structural shapes preserves separate counts',()=>{
  const hints=inferTextHeaderHints(proxy+'\n'+hdfs);
  expect(hints?.inspectedRecords).toBe(4);
  expect(hints?.matchedHeaderRecords).toBe(4);
  expect(hints?.patterns.map(p=>p.records)).toEqual([2,2]);
  expect(hints?.messageSemanticsVerified).toBe(false);
 });
 it('refuses control characters, oversized source or unsupported UTF-8 conversion',()=>{
  expect(inferTextHeaderHints(proxy+'\r')).toBeNull();
  expect(inferTextHeaderHints(proxy+'\x00')).toBeNull();
  expect(inferTextHeaderHints('x'.repeat(65_537))).toBeNull();
 });
});
