import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import ParserIdentityCard from './ParserIdentityCard';

describe('parser identity inputs',()=>{
  it('stop typing at the 128-character project schema limit instead of failing at the final step',()=>{
    render(<ParserIdentityCard draft={createDraft()} setDraft={vi.fn()}/>);
    expect(screen.getByLabelText('Parser manufacturer').getAttribute('maxlength')).toBe('128');
    expect(screen.getByLabelText('Parser product').getAttribute('maxlength')).toBe('128');
  });

  it('warns on the final step while the demo manufacturer/product placeholder is still in use',()=>{
    render(<ParserIdentityCard draft={createDraft()} setDraft={vi.fn()} warnIfPlaceholder/>);
    const warning=screen.getByRole('note',{name:/placeholder/i});
    expect(warning).toHaveTextContent('Demo Local Draft');
    expect(warning).toHaveTextContent('Untitled parser');
    expect(warning).toHaveTextContent(/downloaded files/i);
  });
  it('names only the placeholder that is still unset',()=>{
    const draft={...createDraft(),vendor:'Fortinet'};
    render(<ParserIdentityCard draft={draft} setDraft={vi.fn()} warnIfPlaceholder/>);
    const warning=screen.getByRole('note',{name:/placeholder/i});
    expect(warning).toHaveTextContent('Untitled parser');
    expect(warning).not.toHaveTextContent('Demo Local Draft');
  });
  it('shows no warning once real names are entered, or when the warning is not requested',()=>{
    const real={...createDraft(),vendor:'Fortinet',name:'FortiGate'};
    const {unmount}=render(<ParserIdentityCard draft={real} setDraft={vi.fn()} warnIfPlaceholder/>);
    expect(screen.queryByRole('note',{name:/placeholder/i})).toBeNull();
    unmount();
    render(<ParserIdentityCard draft={createDraft()} setDraft={vi.fn()}/>);
    expect(screen.queryByRole('note',{name:/placeholder/i})).toBeNull();
  });
});
