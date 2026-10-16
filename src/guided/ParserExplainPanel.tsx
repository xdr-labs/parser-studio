import {CheckCircle2,CircleAlert,Info,Route} from 'lucide-react';
import type {EventResult,ParserDraft} from '../model';
import {buildParserExplain} from './parserExplain';

interface Props{
  event:EventResult|undefined;
  draft:ParserDraft;
  multiPassSyntax?:string;
}

export default function ParserExplainPanel({event,draft,multiPassSyntax}:Props){
  const report=buildParserExplain(event,draft,multiPassSyntax);
  if(!event)return null;
  return <details className="parser-explain" open aria-label="How Parser Studio parsed this event">
    <summary><Route size={15}/> How Parser Studio parsed this event</summary>
    <p>Follow the path from event framing to extraction and mapping.
      A local parse result is not presented as native or Stellar target verification.</p>
    <div className="parser-explain-steps">
      {report.steps.map((step,index)=><div key={step.id}
        className={'parser-explain-step '+step.status.toLowerCase()}>
        <div className="parser-explain-step-heading">
          <strong>{index+1}. {step.title}</strong>
          <span>{step.status==='PASS'?'Accepted':step.status==='REVIEW'?'Review':'Evidence'}</span>
        </div>
        <p>{step.summary}</p>
        {!!step.details.length&&<div className="parser-explain-details">
          {step.details.map((detail,detailIndex)=><code key={detailIndex}>{detail}</code>)}
        </div>}
        <span className="sr-only" aria-hidden="true">
          {step.status==='PASS'?<CheckCircle2 size={1}/>:
            step.status==='REVIEW'?<CircleAlert size={1}/>:<Info size={1}/>}
        </span>
      </div>)}
    </div>
  </details>;
}
