import {afterEach,describe,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import DeclaredRelayProfilePanel from './DeclaredRelayProfilePanel';

const tagless='Oct 29 10:00:00 relay-a fortigate: date=2024-08-28 action="info"\nOct 29 10:00:01 relay-a fortigate: date=2024-08-28 action="pass"';
const withPri=tagless.split('\n').map(row=>'<134>'+row).join('\n');

function panel(sample:string){
  render(<DeclaredRelayProfilePanel sample={sample} draft={createDraft()} setDraft={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText('Declared relay hostname list'),{target:{value:'relay-a'}});
}
afterEach(cleanup);

describe('declared relay preview wording',()=>{
  it('says why a header without <PRI> is not recognized',()=>{
    panel(tagless);
    const preview=screen.getByLabelText('Relay source preview').textContent??'';
    expect(preview).toMatch(/0 of 2 events recognized/);
    expect(preview).toMatch(/2 not matching a declared relay/);
    expect(screen.getByText(/begins with a Syslog header that starts with <PRI>/)).toBeTruthy();
    expect(screen.getByText(/A header without <PRI> is not unwrapped/)).toBeTruthy();
  });
  it('shows no explanation when every event is recognized',()=>{
    panel(withPri);
    expect(screen.getByLabelText('Relay source preview').textContent).toMatch(/2 of 2 events recognized/);
    expect(screen.queryByText(/A header without <PRI> is not unwrapped/)).toBeNull();
  });
});
