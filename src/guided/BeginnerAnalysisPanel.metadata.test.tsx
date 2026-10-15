import {describe,it,expect,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import {createDraft} from '../model';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

describe('Beginner metadata preservation review',()=>{
  it('offers an explicit no-inference path for bounded bracket colon-KV metadata',()=>{
    const source='<134>1 2020-03-30T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"]';
    const preview:MultiPassSourcePreview={
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'PARTIAL',syntax:'SECURITY_SYSLOG_BRACKET_COLON_KV',
      sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
      fields:{syslog:{pri:'134',timestamp:'2020-03-30T07:20:35'},body:{action:'Accept',src:'192.0.2.1'}},
      spans:[{path:'syslog.pri',startByte:1,endByte:4}],residuals:[],
      issues:['SOURCE_TIMESTAMP_INVALID'],nativeVerified:false,targetVerified:false,
    };
    const draft=createDraft();
    const apply=vi.fn();
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:preview.sourceBytes,preview}]}
      onOpenAssisted={vi.fn()} draft={draft} onApplyCandidate={apply}/>);
    const preserve=screen.getByRole('button',{name:'Preserve source metadata as text'});
    expect(preserve).toBeTruthy();
    fireEvent.click(preserve);
    expect(apply).toHaveBeenCalledTimes(1);
    const candidate=apply.mock.calls[0]![0];
    expect(candidate.format).toBe('generic_structural');
    expect(candidate.mappings).toEqual([
      {id:'metadata-source-pri',source:'syslog.pri',target:'custom.source_pri',type:'string'},
    ]);
    expect(candidate.guided.classification).toEqual({defaultIndex:'Syslog',rules:[]});
    expect(candidate.mappings.some((item:{source:string;type:string})=>
      item.source==='syslog.timestamp'||item.type==='timestamp')).toBe(false);
  });

  it('does not offer preservation for unrelated metadata anomalies',()=>{
    const source='<1>1 bad';
    const preview:MultiPassSourcePreview={
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'PARTIAL',syntax:'SYSLOG_RFC5424',
      sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
      fields:{},spans:[],residuals:[],issues:['SOURCE_TIMESTAMP_INVALID'],
      nativeVerified:false,targetVerified:false,
    };
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:preview.sourceBytes,preview}]}
      onOpenAssisted={vi.fn()} draft={createDraft()} onApplyCandidate={vi.fn()}/>);
    expect(screen.queryByRole('button',{name:'Preserve source metadata as text'})).toBeNull();
    expect(screen.getByRole('button',{name:'Review with ChatGPT'})).toBeTruthy();
  });
});