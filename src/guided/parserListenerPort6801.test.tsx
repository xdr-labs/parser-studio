import {useState} from 'react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import AutoParser from './AutoParser';
import {toBackendProject} from './backendAdapter';
import {DEFAULT_PARSER_LISTENER_PORT} from './contract';

function NoviceEntry(){
  const [draft,setDraft]=useState(createDraft);
  const exactBackend=toBackendProject({...draft,format:'json'});
  return <>
    <AutoParser draft={draft} setDraft={setDraft}
      sample="" setSample={vi.fn()} datasetName="No logs uploaded"
      setDatasetName={vi.fn()} namedLogTypes={null}
      onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
      onExitNamedLogTypes={vi.fn()} pending={false} runPreview={vi.fn()}
      onChatGPT={vi.fn()} advanced={false}/>
    <output data-testid="backend-port">
      {exactBackend.ok ? exactBackend.project.receiver.port : 'INVALID'}
    </output>
  </>;
}

afterEach(()=>cleanup());

describe('novice source identity listener port',()=>{
  it('starts new drafts at 6801 before any logs and sends the same value to the compiler project',()=>{
    expect(DEFAULT_PARSER_LISTENER_PORT).toBe(6801);
    render(<NoviceEntry/>);
    const stage=screen.getByRole('region',{name:'Add Logs stage'});
    const field=screen.getByRole('spinbutton',{name:'Parser listener port'});
    expect(stage.contains(field)).toBe(true);
    expect(field).toHaveValue(6801);
    expect(screen.getByTestId('backend-port')).toHaveTextContent('6801');
    expect(screen.getByText('Generated .conf receiving port: 6801')).toBeVisible();
    expect(screen.getByRole('button',{name:'Analyze Logs'})).toBeDisabled();
  });
  it('retains explicit override for the actual draft without touching raw source or claiming a socket',()=>{
    render(<NoviceEntry/>);
    const field=screen.getByRole('spinbutton',{name:'Parser listener port'});
    fireEvent.change(field,{target:{value:'6819'}});
    expect(field).toHaveValue(6819);
    expect(screen.getByTestId('backend-port')).toHaveTextContent('6819');
    expect(screen.getByText('Generated .conf receiving port: 6819')).toBeVisible();
    expect(screen.getByRole('textbox',{name:'Auto Parser raw logs'})).toBeEmptyDOMElement();
    fireEvent.change(field,{target:{value:'80'}});
    expect(field).toHaveAttribute('aria-invalid','true');
    expect(screen.getByTestId('backend-port')).toHaveTextContent('INVALID');
  });
});
