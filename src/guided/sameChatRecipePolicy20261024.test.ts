/** Same-chat assistant-authored regex proposals, NOT separate ChatGPT provider runs.
 * Qualifies strict v0.2 syntax/validation and malformed holdout refusals.
 */
import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {validateReviewableRecipe} from './parserRecipeV2';
import {validatePreviewRegexPattern} from '../regexSafety';

const proposed={
  bracket:String.raw`^\[(?<month_day>(?:0[1-9]|1[0-2])\.(?:0[1-9]|[12]\d|3[01])) (?<clock>(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)\] (?<application>[A-Za-z0-9_.+-]+(?: \*64)?) - (?<target_host>[A-Za-z0-9_.-]+):(?<target_port>\d{1,5}) (?<message>[^\r\n]+)$`,
  logcat:String.raw`^(?<month_day>(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])) (?<clock>(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3})\s+(?<pid>\d{1,7})\s+(?<tid>\d{1,7}) (?<priority>[VDIWEFS]) (?<tag>[A-Za-z0-9_.$/-]+): (?<message>[^\r\n]+)$`,
} as const;
function candidate(pattern:string,raw:string){
  const stages=[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_regex',pattern},
    {op:'map_field',source:'message',target:'custom.message',data_type:'string',group:'vendor_fields'},
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
  ];
  return {contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
   projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
   sample:{sha256:createHash('sha256').update(raw).digest('hex'),events:1},
   stages,nativeVerified:false,targetVerified:false};
}
describe('strict same-session GPT-6 recipe candidates (not independent provider evaluation)',()=>{
 it('bounded named-capture regex recipes meet strict ParserRecipe v0.2 schema',()=>{
   for(const [key,pattern] of Object.entries(proposed)){
     const raw=key==='bracket'?
      '[10.30 16:49:06] app.exe - host.example:443 connection opened':
      '03-17 16:13:38.811  1702  2395 D WindowManager: visible';
     expect(pattern.length).toBeLessThanOrEqual(256);
     expect(validatePreviewRegexPattern(pattern)).toBeNull();
     expect(validateReviewableRecipe(candidate(pattern,raw))).toBe(true);
     expect(new RegExp(pattern).exec(raw)?.groups?.message).toBeTruthy();
   }
 });
 it('rejects obvious malformed times, invalid month and unframed source rather than overfitting',()=>{
   const bracket=new RegExp(proposed.bracket),logcat=new RegExp(proposed.logcat);
   const wrong=[
     '[13.99 25:61:99] app.exe - host.example:443 invalid',
     '[02.31 25:30:00] app.exe - host.example:443 invalid',
     '[10.30 25:20:00] app.exe - host.example:443 invalid',
     '03-17 16:13:38.811  1702  2395 D WindowManager: visible\nsecond',
   ];
   for(const raw of wrong)expect(bracket.test(raw)).toBe(false);
   for(const raw of [
     '13-35 25:61:99.819  1702  8671 W ActivityManager: invalid',
     '03-17 24:13:38.819  1702  8671 W ActivityManager: invalid',
     '03-17 16:60:38.819  1702  8671 W ActivityManager: invalid',
   ])expect(logcat.test(raw)).toBe(false);
 });
});
