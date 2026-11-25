/**
 * The Auto Parser repair prompt ("Fix with ChatGPT") states the export rule of a parse_regex recipe (2026-11-25).
 *
 * The ChatGPT Assisted Parser prompt told the model that a Regex is exported for Stellar Cyber 7.0 (Ruby 2.4.9, no
 * Regexp timeout) only when it is anchored and its backtracking is statically bounded. The repair prompt did not, so a
 * reply such as (?<ts>\S+)\|...(?<proto>[^|]+)... passed the fix test, was applied, and was then stopped at Review
 * Fields as not exportable. Both prompts state the same rule now.
 */
import {expect,it} from 'vitest';
import {buildBeginnerRepairPrompt} from './beginnerAiPrompt';
import {REGEX_EXPORT_TARGET_RULE} from './chatGptPromptBuilder';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

const SOURCE='2026-11-25T00:10:10Z|sensor=ids-4|sip=10.80.8.8|dip=203.0.113.80|sport=12345|dport=53|proto=UDP|alert=DNS tunneling';
const bytes=(text:string)=>new TextEncoder().encode(text).byteLength;

it('the repair prompt states when a parse_regex recipe can be exported for the Stellar Cyber 7.0 target',async()=>{
  const preview:MultiPassSourcePreview={
    contract:'parser-studio.multipass-source-preview.v0.1',
    status:'PARTIAL',syntax:'UNKNOWN+GENERIC_ATOMS',
    sourceSha256:'a'.repeat(64),sourceBytes:bytes(SOURCE),
    fields:{generic_atoms:{network:['10.80.8.8','203.0.113.80']}},
    spans:[{path:'generic_atoms.network[0]',startByte:38,endByte:47},{path:'generic_atoms.network[1]',startByte:52,endByte:64}],
    residuals:[{startByte:0,endByte:38},{startByte:47,endByte:52},{startByte:64,endByte:bytes(SOURCE)}],
    issues:['NO_SUPPORTED_GRAMMAR'],nativeVerified:false,targetVerified:false,
  };
  const prompt=await buildBeginnerRepairPrompt({
    fullSource:SOURCE,eventSource:SOURCE,preview,
    recommendation:{label:'Create a rule for this text format',text:'Use the repeated separators or text pattern.'},
  });
  expect(REGEX_EXPORT_TARGET_RULE).toContain('anchored (^...$)');
  expect(REGEX_EXPORT_TARGET_RULE).toContain('no two adjacent repetitions that can match the same characters');
  expect(prompt).toContain(REGEX_EXPORT_TARGET_RULE);
});
