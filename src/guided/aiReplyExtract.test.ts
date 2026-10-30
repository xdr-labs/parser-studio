import {describe,it,expect} from 'vitest';
import {extractRecipeJson} from './aiReplyExtract';

const RECIPE={contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',projectId:'draft-abc',stages:[{op:'map_field',a:'x}y'}]};
const JSON_TEXT=JSON.stringify(RECIPE,null,2);

describe('extractRecipeJson',()=>{
  it('returns bare JSON unchanged and reports nothing ignored',()=>{
    const r=extractRecipeJson('  '+JSON_TEXT+'\n');
    expect(r).toEqual({text:JSON_TEXT,ignoredText:false});
  });
  it('strips one wrapping fence without calling it ignored prose',()=>{
    const r=extractRecipeJson('```json\n'+JSON_TEXT+'\n```');
    expect(r).toEqual({text:JSON_TEXT,ignoredText:false});
  });
  it('filters prose before and after a single fenced block',()=>{
    const r=extractRecipeJson('Sure! Here is the recipe:\n\n```json\n'+JSON_TEXT+'\n```\n\nLet me know if you need changes.');
    expect(r).toEqual({text:JSON_TEXT,ignoredText:true});
  });
  it('filters prose around an unfenced JSON object, ignoring braces inside strings',()=>{
    const r=extractRecipeJson('Here you go {not json}:\n'+JSON_TEXT+'\nHope it helps {src_ip}.');
    expect(r).toEqual({text:JSON_TEXT,ignoredText:true});
  });
  it('prefers the recipe when prose also contains another valid JSON object',()=>{
    const r=extractRecipeJson('Example: {"a":1}\n```json\n'+JSON_TEXT+'\n```');
    expect(r?.text).toBe(JSON_TEXT);
    expect(r?.ignoredText).toBe(true);
  });
  it('refuses to guess between two recipe candidates',()=>{
    const other=JSON.stringify({...RECIPE,projectId:'draft-other'});
    expect(extractRecipeJson(JSON_TEXT+'\nor\n'+other)).toBeNull();
  });
  it('returns null for pure diagnosis or prose without JSON',()=>{
    expect(extractRecipeJson('REVIEW_REQUIRED: no timezone')).toBeNull();
    expect(extractRecipeJson('Sure! Here is how I would parse it.')).toBeNull();
    expect(extractRecipeJson('')).toBeNull();
  });
  it('returns null for truncated JSON inside prose',()=>{
    expect(extractRecipeJson('Here: {"contract":"parser-studio.recipe.v0.2",')).toBeNull();
  });
});
