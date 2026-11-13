import {describe,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {createDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';

// Auto Parser warns, at its final step, that the demo manufacturer/product placeholder would be
// written into the downloaded files. The ChatGPT Assisted path must warn before it creates them too.
const sample='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=10.0.0.10 dstip=10.0.0.20 dstport=443';

function renderAssist(draft:ReturnType<typeof createDraft>){
  const suite=preview(sample,draft);
  render(<ChatGPTAssist draft={draft} setDraft={vi.fn()} sample={sample}
    setSample={vi.fn()} namedLogTypes={null}
    onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
    onExitNamedLogTypes={vi.fn()} suite={suite} pending={false}
    runPreview={async()=>suite} onAutoParser={vi.fn()}/>);
}

async function acceptBaselineRecipe(){
  fireEvent.click(screen.getByRole('button',{name:'Prepare ChatGPT Prompt'}));
  const prompt=await screen.findByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement;
  const begin='----- BEGIN VALIDATED BASELINE RECIPE -----',end='----- END VALIDATED BASELINE RECIPE -----';
  const recipe=prompt.value.slice(prompt.value.indexOf(begin)+begin.length,prompt.value.indexOf(end)).trim();
  fireEvent.change(screen.getByLabelText('ChatGPT result JSON'),{target:{value:recipe}});
  fireEvent.click(screen.getByRole('button',{name:'Check ChatGPT Result'}));
  await screen.findByText(/ChatGPT result accepted for testing/i);
}

describe('ChatGPT Assisted Parser placeholder identity',()=>{
  it('warns before files are created while the demo manufacturer/product placeholder is unchanged',async()=>{
    renderAssist({...createDraft(),format:'kv' as const});
    expect(screen.queryByRole('note',{name:/placeholder/i})).toBeNull();
    await acceptBaselineRecipe();
    const warning=await waitFor(()=>screen.getByRole('note',{name:/placeholder/i}));
    expect(warning).toHaveTextContent('Demo Local Draft');
    expect(warning).toHaveTextContent(/downloaded files/i);
  });
  it('shows no placeholder warning once real names are entered',async()=>{
    renderAssist({...createDraft(),format:'kv' as const,vendor:'Fortinet',name:'FortiGate'});
    await acceptBaselineRecipe();
    expect(screen.queryByRole('note',{name:/placeholder/i})).toBeNull();
  });
});
