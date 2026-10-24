/** Conservative local source grammar observations for the manually copied
 * ChatGPT prompt. These are syntax observations, never native/parser or vendor
 * correctness evidence. Original user bytes remain separately authoritative.
 */
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {inspectZeekReview} from './zeekReview';
import {inferTextHeaderHints} from './textHeaderHints';

export interface PromptSourceEvidence{
 text:string;
 originalPhysicalRecordCount:number;
 schema:'ZEEK_DECLARED'|'W3C_DECLARED'|null;
 headerLines:number|null;
 logicalDataRows:number|null;
}

interface DeclaredRows{
 schema:NonNullable<PromptSourceEvidence['schema']>;
 headerLines:number;
 logicalDataRows:number;
}

function inspectW3cRows(source:string):DeclaredRows|null{
 if(source.includes('\r'))return null;
 const lines=source.split('\n').filter(Boolean);
 if(lines.length<2||lines.some(line=>line.length>8192))return null;
 const fields=lines.filter(line=>line.startsWith('#Fields: '));
 if(fields.length!==1)return null;
 const names=fields[0]!.slice('#Fields: '.length).split(/ +/);
 if(names.length<2||names.length>100||
    names.some(name=>!/^[A-Za-z][A-Za-z0-9_.()-]{0,63}$/.test(name))||
    new Set(names).size!==names.length)return null;
 const header=/^#(?:Version|Fields|Date|Software|Remark|Start-Date|End-Date):\s/;
 const meta=lines.filter(line=>line.startsWith('#'));
 if(meta.some(line=>!header.test(line)))return null;
 // A later or interleaved schema line cannot retroactively describe data.
 if(lines.some((line,i)=>line.startsWith('#')&&lines.slice(0,i).some(prev=>!prev.startsWith('#'))))return null;
 const rows=lines.filter(line=>!line.startsWith('#'));
 if(!rows.length||rows.length>500||rows.some(line=>line.trim().split(/ +/).length!==names.length))
  return null;
 return {schema:'W3C_DECLARED',headerLines:meta.length,logicalDataRows:rows.length};
}

export function buildPromptSourceEvidence(source:string):PromptSourceEvidence{
 const ledger=analyzeLogEnvelopes(source,'single-line');
 const zeek=inspectZeekReview(source);
 const declared:DeclaredRows|null=zeek
   ?{schema:'ZEEK_DECLARED',headerLines:zeek.metadataCount,logicalDataRows:zeek.recordCount}
   :inspectW3cRows(source);
 const metadata={
   preliminaryPhysicalSourceRecords:ledger.sourceCount,
   unrecognizedSourceRecords:ledger.unsupported,
   detectedFamilies:ledger.families.map(f=>({
     envelope:f.envelope,body:f.body,count:f.count,
   })),
   nativeVerified:false,
   targetVerified:false,
 };
 const sentences=[
   'Parser Studio preliminary local source-format observations (unverified, not a vendor oracle):',
   JSON.stringify(metadata),
 ];
 const textHeader=inferTextHeaderHints(source);
 if(textHeader){
   sentences.push(
     'Bounded header-only text layout observations (fixed identifiers and counts only, not decoded vendor values):',
     JSON.stringify(textHeader),
     'IMPORTANT: extracting a header or preserving a whole message is NOT proof of semantic fields such as username, action, source IP, or a compiler-ready parser.',
     'For REVIEW_ONLY parse_regex proposals, capture only demonstrably delimited values with named groups; do not embed observed hostnames, IPs, identifiers or timestamps as fixed literals. Do not guess a missing year or timezone.',
     'Check every event shape in the original source AND distinct holdout examples before accepting a recipe. If source shapes conflict or field boundaries are ambiguous, respond REVIEW_REQUIRED: with the exact missing evidence.',
   );
 }
 if(declared){
   sentences.push(
     'Recognized a declared-schema source whose header lines are metadata, not data events:',
     JSON.stringify(declared),
     'IMPORTANT: the exact sample.events/sourceCount identity refers to '+
       ledger.sourceCount+' original physical source records, not the logical data-event count ('+
       declared.logicalDataRows+'). Retain the original digest and source unchanged.',
     'This original header-dependent stream has no deployable recipe in its present form and is NOT a verified downloadable single-line ParserRecipe grammar. '+
       'Respond REVIEW_REQUIRED: and explain the exact declared header/column and event framing review. '+
       'Do not invent a schema-free single-line recipe, silently discard the metadata lines, '+
       'or claim this source is parser-ready. The user may prepare a separately reviewed data-only sample in Auto Parser.',
   );
 }
 return {
   text:sentences.join('\n'),
   originalPhysicalRecordCount:ledger.sourceCount,
   schema:declared?.schema??null,
   headerLines:declared?.headerLines??null,
   logicalDataRows:declared?.logicalDataRows??null,
 };
}
