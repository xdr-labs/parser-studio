import type {ComponentProps} from 'react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {createDraft} from '../model';
import AutoParser from './AutoParser';
import type {BackendCapabilities} from './backendCapabilities';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

const cases=[
  {name:'Syslog description and KV',profile:'syslog_prefix_kv' as const,
    raw:'<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block'},
  {name:'implicit-TAB LEEF',profile:'leef2_implicit_tab' as const,
    raw:'LEEF:2.0|Zscaler|NSS|1.0|web-block|\tusrName=alice\tsrc=192.0.2.6\tdst=198.51.100.4\turl=https://example.test/login\taction=blocked'},
];

function capabilities(profiles?:BackendCapabilities['authoring']['genericStructuralProfiles']):BackendCapabilities{
  return {
    contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
    authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['generic_structural'],
      genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',
      ...(profiles?{genericStructuralProfiles:profiles}:{}),formatCoverage:'reviewed-bounded-subset',
      httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
    import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
    verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
    limits:{maxProjectBodyBytes:256*1024,maxInspectBodyBytes:2*1024*1024},
  };
}

function candidateProps(raw:string):ComponentProps<typeof AutoParser>{
  const prepared=buildAutomaticGenericStructuralDraft(raw,createDraft());
  if(!prepared)throw new Error('Expected the original corpus source to produce an explicit browser draft');
  return {
    draft:prepared.draft,setDraft:vi.fn(),sample:raw,setSample:vi.fn(),
    namedLogTypes:null,onEnableNamedLogTypes:vi.fn(),onChangeNamedLogTypes:vi.fn(),onExitNamedLogTypes:vi.fn(),
    datasetName:'Compatibility fixture',setDatasetName:vi.fn(),suite:prepared.suite,pending:false,
    runPreview:vi.fn().mockResolvedValue(prepared.suite),onChatGPT:vi.fn(),advanced:false,
  };
}

afterEach(()=>{cleanup();vi.unstubAllGlobals();});

describe('explicit parser profile compatibility at the field-review transition',()=>{
  it.each(cases)('preserves $name and provides a retryable block until its profile is advertised',async item=>{
    let available=capabilities();
    const request=vi.fn(async(url:RequestInfo|URL,init?:RequestInit)=>{
      expect(String(url)).toBe('/api/v1/parser-pairs/capabilities');
      expect(init?.method).toBe('GET');
      expect(init?.body).toBeUndefined();
      return new Response(JSON.stringify(available),{status:200,headers:{'Content-Type':'application/json'}});
    });
    vi.stubGlobal('fetch',request);
    const props=candidateProps(item.raw);
    expect(props.draft.genericStructuralProfile).toBe(item.profile);
    const before=JSON.stringify({draft:props.draft,suite:props.suite});
    render(<AutoParser {...props}/>);
    fireEvent.click(screen.getByRole('button',{name:'Review Fields'}));
    const blocked=await screen.findByRole('alert',{name:'Parser draft not ready'});
    expect(blocked).toHaveTextContent('The connected parser creation service does not support this draft');
    expect(blocked).toHaveTextContent('Update or restart the development backend');
    expect(blocked).toHaveTextContent('Re-check parser support and Review Fields');
    expect(blocked).toHaveTextContent('No source value was discarded');
    expect(screen.getByRole('button',{name:'Review Fields'})).toBeDisabled();
    expect(screen.queryByRole('region',{name:'Review Fields stage'})).toBeNull();
    expect(screen.getByRole('textbox',{name:'Auto Parser raw logs'})).toHaveValue(item.raw);
    fireEvent.click(within(blocked).getByRole('button',{name:'Use ChatGPT Assisted Parser'}));
    expect(props.onChatGPT).toHaveBeenCalledTimes(1);
    expect(props.setDraft).not.toHaveBeenCalled();
    expect(props.setSample).not.toHaveBeenCalled();
    expect(JSON.stringify({draft:props.draft,suite:props.suite})).toBe(before);
    expect(request).toHaveBeenCalledTimes(1);

    available=capabilities([item.profile]);
    fireEvent.click(within(blocked).getByRole('button',{name:'Re-check parser support'}));
    expect(screen.queryByRole('alert',{name:'Parser draft not ready'})).toBeNull();
    expect(screen.getByRole('button',{name:'Review Fields'})).toBeEnabled();
    fireEvent.click(screen.getByRole('button',{name:'Review Fields'}));
    await screen.findByRole('region',{name:'Review Fields stage'});
    expect(request).toHaveBeenCalledTimes(2);
    expect(screen.getByLabelText('Browser-only event inspector').querySelector('pre')?.textContent).toBe(item.raw);
    expect(JSON.stringify({draft:props.draft,suite:props.suite})).toBe(before);
    expect(props.setDraft).not.toHaveBeenCalled();
    expect(props.setSample).not.toHaveBeenCalled();
  });

  it('keeps a network failure retryable without labeling it as a missing parser profile',async()=>{
    vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    const props=candidateProps(cases[0]!.raw);
    render(<AutoParser {...props}/>);
    fireEvent.click(screen.getByRole('button',{name:'Review Fields'}));
    await screen.findByText(/The parser creation service is unavailable or access was denied/);
    expect(screen.queryByRole('alert',{name:'Parser draft not ready'})).toBeNull();
    expect(screen.getByRole('button',{name:'Review Fields'})).toBeEnabled();
    expect(screen.getByRole('textbox',{name:'Auto Parser raw logs'})).toHaveValue(props.sample);
    expect(props.setDraft).not.toHaveBeenCalled();
    expect(props.setSample).not.toHaveBeenCalled();
  });

  it('does not attach a delayed profile failure to a replacement source',async()=>{
    let reject!:(reason:Error)=>void;
    const pending=new Promise<Response>((_resolve,fail)=>{reject=fail;});
    const request=vi.fn(()=>pending);
    vi.stubGlobal('fetch',request);
    const first=candidateProps(cases[0]!.raw);
    const {rerender}=render(<AutoParser {...first}/>);
    fireEvent.click(screen.getByRole('button',{name:'Review Fields'}));
    await waitFor(()=>expect(request).toHaveBeenCalledTimes(1));
    const replacement=candidateProps(cases[1]!.raw);
    rerender(<AutoParser {...replacement}/>);
    await act(async()=>{
      reject(Object.assign(new Error('The backend does not advertise the selected Generic Structural profile.'),
        {code:'BACKEND_PROFILE_UNSUPPORTED'}));
      await pending.catch(()=>undefined);
    });
    expect(screen.queryByRole('alert',{name:'Parser draft not ready'})).toBeNull();
    expect(screen.queryByText(/does not support this draft's log structure yet/)).toBeNull();
    expect(screen.getByRole('button',{name:'Review Fields'})).toBeEnabled();
    expect(screen.getByRole('textbox',{name:'Auto Parser raw logs'})).toHaveValue(replacement.sample);
    expect(replacement.setDraft).not.toHaveBeenCalled();
    expect(replacement.setSample).not.toHaveBeenCalled();
  });
});
