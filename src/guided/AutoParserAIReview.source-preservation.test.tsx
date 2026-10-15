import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import AutoParserAIReview from './AutoParserAIReview';

it('accepts source values preserved by reviewed enrichment outputs',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10\ndeny,203.0.113.4';
 const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<pair>[^,]+,[^,]+)$'},
   {op:'map_field',source:'pair',target:'custom.buffer',data_type:'string',group:'top_fields'},
   {op:'split_field',source:'custom.buffer',delimiter:',',targets:['custom.action','custom.src_ip']},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['allow','198.51.100.10'],['deny','203.0.113.4']]}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 vi.unstubAllGlobals();
});
