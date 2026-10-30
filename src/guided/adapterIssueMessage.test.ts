import {describe,it,expect} from 'vitest';
import {describeAdapterIssues} from './adapterIssueMessage';

describe('describeAdapterIssues',()=>{
  it('explains an unusable declared relay in plain words',()=>{
    const text=describeAdapterIssues([{code:'FORWARDER_FORMAT_UNSUPPORTED',path:'/forwarder',
      message:'The selected format does not support declared relays.'}]);
    expect(text).toMatch(/relay/i);
    expect(text).toMatch(/cannot be used|can't be used/i);
    expect(text).not.toMatch(/classification setting/);
  });

  it('explains invalid relay settings with the adapter requirement',()=>{
    const text=describeAdapterIssues([{code:'INVALID_FORWARDER_PROFILE',path:'/forwarder',
      message:'Declare valid distinct relay hosts and 1–3 hops.'}]);
    expect(text).toMatch(/relay/i);
    expect(text).toContain('Declare valid distinct relay hosts and 1–3 hops.');
  });

  it('shows the first adapter message for other problems',()=>{
    const text=describeAdapterIssues([{code:'DUPLICATE_SOURCE',path:'/mappings/1',
      message:'This source is already mapped in the same output group: src'}]);
    expect(text).toContain('This source is already mapped in the same output group: src');
  });

  it('falls back to a generic sentence when there is no issue text',()=>{
    expect(describeAdapterIssues([])).toMatch(/could not be turned into a parser/i);
  });
});
