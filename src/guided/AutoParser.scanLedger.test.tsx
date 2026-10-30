import type {ComponentProps} from 'react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {cleanup,render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import AutoParser from './AutoParser';

const sample='<34>Oct 30 10:00:00 host sshd[1]: Accepted password for user1 from 192.0.2.1 port 22 ssh2\n';

function props(extra:Partial<ComponentProps<typeof AutoParser>>={}):ComponentProps<typeof AutoParser>{
  return {
    draft:createDraft(),setDraft:vi.fn(),sample,setSample:vi.fn(),
    namedLogTypes:null,onEnableNamedLogTypes:vi.fn(),onChangeNamedLogTypes:vi.fn(),onExitNamedLogTypes:vi.fn(),
    datasetName:'Ledger fixture',setDatasetName:vi.fn(),suite:undefined,pending:false,
    runPreview:vi.fn(),onChatGPT:vi.fn(),advanced:false,...extra,
  };
}

afterEach(()=>cleanup());

describe('initial format scan strip',()=>{
  it('is folded for a beginner so it does not compete with the parse summary',()=>{
    render(<AutoParser {...props()}/>);
    const ledger=screen.getByLabelText('Automatic event accounting');
    expect(ledger.tagName).toBe('DETAILS');
    expect((ledger as HTMLDetailsElement).open).toBe(false);
    // the one-line summary stays visible and the detail text is still in the page
    expect(ledger.querySelector('summary')).toHaveTextContent('Initial format scan');
    expect(ledger).toHaveTextContent('not a parser completeness result');
  });

  it('stays open in advanced mode',()=>{
    render(<AutoParser {...props({advanced:true})}/>);
    expect((screen.getByLabelText('Automatic event accounting') as HTMLDetailsElement).open).toBe(true);
  });
});
