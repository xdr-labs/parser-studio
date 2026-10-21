import {useState} from 'react';
import {describe,it,expect} from 'vitest';
import {fireEvent,render,screen,within} from '@testing-library/react';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import ReviewedEventProfilesPanel from './ReviewedEventProfilesPanel';

const raw=[
  '{"event_type":"threat","src_ip":"192.0.2.10","sha256":"'+('a'.repeat(32))+'"}',
  '{"event_type":"threat","src_ip":"192.0.2.11","sha256":"'+('b'.repeat(32))+'"}',
  '{"event_type":"user","username":"山田"}',
  '{"event_type":"user","username":"김민수"}',
].join('\n');
const backendCapabilities:BackendCapabilities={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json'],
    formatCoverage:'reviewed-bounded-subset',conditionalEventProfiles:true,
    conditionalEventProfilesUnknownPolicy:'reject',
    httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:256*1024,maxInspectBodyBytes:2*1024*1024},
};

function Harness(){
  const [draft,setDraft]=useState<ParserDraft>({...createDraft(),format:'json',mappings:[]});
  const suite=preview(raw,draft);
  return <>
    <ReviewedEventProfilesPanel suite={suite} draft={draft} setDraft={setDraft}
      backendCapabilities={backendCapabilities} source={raw} pending={false} highlightNamed/>
    <pre aria-label="Pending draft">{JSON.stringify(draft)}</pre>
  </>;
}
describe('beginner reviewed multi-type fixed 7.0 mapping UX',()=>{
  it('requires an explicit per-family recommendation click and separate approval',()=>{
    render(<Harness/>);
    const panel=screen.getByLabelText('Configure one parser for event types');
    const threat=within(panel).getByLabelText('Type-specific mappings for threat');
    fireEvent.click(threat.querySelector('summary')!);
    expect(within(threat).getByLabelText('threat output for src_ip')).toHaveValue('custom.src_ip');
    expect(within(threat).getByText(/Stellar Cyber 7.0: src_ip → srcip/)).toBeInTheDocument();
    const selected=within(threat).getByRole('button',{name:'Use Stellar 7.0 threat src_ip'});
    expect(selected).toBeEnabled();
    expect(within(threat).queryByRole('button',{name:'Use Stellar 7.0 threat sha256'})).toBeNull();
    expect(within(threat).getByText(/Review only/)).toBeInTheDocument();
    fireEvent.click(selected);
    expect(within(threat).getByLabelText('threat output for src_ip')).toHaveValue('srcip');
    // A suggestion click edits only the proposed candidate. User approval
    // and backend capability validation still gate changes to the draft.
    const stored=screen.getByLabelText('Pending draft').textContent!;
    expect(stored).not.toContain('"eventProfiles"');
    fireEvent.click(within(panel).getByLabelText('Approve explicit family routing changes'));
    fireEvent.click(within(panel).getByRole('button',{name:'Apply reviewed event types to this parser'}));
    const reviewed=JSON.parse(screen.getByLabelText('Pending draft').textContent!) as ParserDraft;
    expect(reviewed.eventProfiles?.unknown).toBe('reject');
    const mapping=reviewed.eventProfiles?.variants.find(x=>x.name==='threat')
      ?.mappings.find(x=>x.source==='src_ip');
    expect(mapping).toMatchObject({target:'srcip',type:'ip'});
    expect(reviewed.guided?.groups[mapping!.id]).toBe('top_fields');
    const adapted=toBackendProject(reviewed);
    expect(adapted.ok).toBe(true);
    if(adapted.ok)
      expect(adapted.project.normalization.eventProfiles?.variants.find(x=>x.name==='threat')
        ?.topFields.src_ip).toMatchObject({normalized_name:'srcip',data_type:'ip'});
  });
});
