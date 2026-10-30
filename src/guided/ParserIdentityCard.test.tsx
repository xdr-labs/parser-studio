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
});
