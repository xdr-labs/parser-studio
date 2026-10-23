import {describe,it,expect,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import {createDraft} from '../model';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

describe('Beginner metadata preservation review',()=>{

  it('explains W3C/Zeek header-line accounting without treating headers as events',()=>{
    const source='2026-10-23 08:11:22 192.0.2.12 GET /admin 403';
    const preview:MultiPassSourcePreview={
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'PARTIAL',syntax:'W3C_EFL_DECLARED',
      sourceSha256:'0'.repeat(64),
      sourceBytes:new TextEncoder().encode(source).byteLength,
      fields:{date:'2026-10-23',time:'08:11:22'},
      spans:[],residuals:[],issues:['SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER'],
      nativeVerified:false,targetVerified:false,
    };
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:preview.sourceBytes,preview}]}
      onOpenAssisted={()=>{}} metadataLineCount={2}/>);
    expect(screen.getByLabelText('Source header versus data event explanation'))
      .toHaveTextContent(/1 data event.*2 schema\/header lines/);
    expect(screen.getByLabelText('Beginner analysis summary'))
      .toHaveTextContent('0 of 1 log event parsed completely');
    expect(screen.getByLabelText('Beginner analysis summary'))
      .not.toHaveTextContent('3 log events parsed');
  });


  it('does not call source-complete positional CSV parser-ready while schema review is pending',()=>{
    const source='alpha,beta,gamma';
    const preview:MultiPassSourcePreview={
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'SOURCE_PARSED',
      syntax:'CSV_UNLABELED',
      sourceSha256:'0'.repeat(64),
      sourceBytes:source.length,
      fields:{csv:['alpha','beta','gamma']},
      spans:[],
      residuals:[],
      issues:[],
      nativeVerified:false,
      targetVerified:false,
    };
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:source.length,preview}]}
      onOpenAssisted={()=>{}}
      csvReviewRequired csvConsistentShapeAvailable={false}/>);
    expect(screen.getByLabelText('Beginner analysis summary'))
      .toHaveTextContent('Values found in 1 of 1 log event');
    expect(screen.queryByText(/parsed completely/)).not.toBeInTheDocument();
    expect(screen.getByText(/do not share one consistent CSV shape/)).toBeInTheDocument();
  });


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
    const preserve=screen.getByRole('button',{name:'Keep the affected header/time value as text'});
    expect(preserve).toBeTruthy();
    fireEvent.click(preserve);
    expect(apply).toHaveBeenCalledTimes(1);
    const candidate=apply.mock.calls[0]![0];
    expect(candidate.format).toBe('generic_structural');
    expect(candidate.mappings).toEqual([
      {id:'metadata-source-pri',source:'syslog.pri',target:'source_pri',type:'string'},
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
    expect(screen.queryByRole('button',{name:'Keep the affected header/time value as text'})).toBeNull();
    expect(screen.getByText(/cannot safely create parser files while this header or time issue remains/)).toBeTruthy();
    expect(screen.getByText(/ChatGPT can explain the problem, but Parser Studio will not guess/)).toBeTruthy();
    expect(screen.getByRole('button',{name:'Review with ChatGPT'})).toBeTruthy();
  });
});