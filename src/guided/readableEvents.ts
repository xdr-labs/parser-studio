/**
 * The events of a sample that the Auto Parser read completely, and the events it did not (Phase 3, P2; owner
 * decision of 2026-11-22: events that cannot be parsed do not stop the creation of a parser for those that can).
 *
 * Every event has its own verdict. A parser is created for the events whose verdict is FULL; the others are
 * named with their kind and their number and never shown as parsed. At run time the generated parser marks
 * such an event as not parsed (parser_err_msg, backend/templates/canonical-operators.rb.tpl) and keeps its
 * complete original text in parser_raw_msg, the Stellar Cyber 7.0 dictionary field for the raw message of a
 * parsing error (owner decision of 2026-11-22), so the parser never drops the event.
 *
 * The split uses the verdicts the Auto Parser goes on with. With the automatic draft these are the server analysis
 * (every event SOURCE_PARSED) and the first scan (every event RECOGNIZED); the browser preview alone is not enough.
 * An event one of them refuses is not readable, so the sample of readable events can always go on (2026-11-25).
 */
import type {SuiteResult} from '../model';
import {splitEvents,MAX_EVENTS} from '../parser';

export interface ExcludedEvents{
  /** Why the events are not covered, in the words shown to the user. */
  kind:string;
  count:number;
  /** One-based numbers of the events in the original sample. */
  events:number[];
}
export interface ReadableEvents{
  /** The readable events, one per line, in their original order. */
  source:string;
  count:number;
  total:number;
  excluded:ExcludedEvents[];
}
interface ScannedEvent{envelope:string;body:string;status:string}

const ENVELOPE_NAMES:Readonly<Record<string,string>>={rfc3164:'RFC 3164 Syslog',rfc5424:'RFC 5424 Syslog'};
const BODY_NAMES:Readonly<Record<string,string>>={kv:'key=value',json:'JSON',cef:'CEF',leef:'LEEF',csv:'delimited'};

/** The kind of an event that was not read completely: what the first scan and the native verdict say. */
function excludedKind(scan:ScannedEvent|undefined,verdict:string):string{
  if(verdict==='PARTIAL')return 'partly read: some values were not extracted';
  if(!scan)return 'unrecognized format';
  const envelope=ENVELOPE_NAMES[scan.envelope];
  // The envelope of a header that could not be read is not established (an RFC 5424 line with VERSION 2 is scanned
  // as a damaged RFC 3164 header), so no envelope is named.
  if(scan.status==='HEADER_MALFORMED')return 'Syslog header that could not be read';
  if(scan.envelope==='none'&&scan.body==='csv')return 'delimited record without column names';
  const body=BODY_NAMES[scan.body];
  if(scan.status==='BODY_MALFORMED'&&body)return (envelope?envelope+' with a ':'')+body+' body that could not be read';
  if(scan.body==='unknown'||!body)return 'unrecognized format';
  return (envelope?envelope+' with a ':'')+body+' body that was not read completely';
}

/**
 * Splits a single-line sample into the events read completely (FULL) and the others. Returns null when there
 * is nothing to split: no event or every event is readable, no event is readable (the sample needs another
 * route, for example ChatGPT Assisted), or the suite does not describe the sample line by line.
 */
export function readableEvents(sample:string,suite:Pick<SuiteResult,'events'>|null|undefined,
  scan:readonly ScannedEvent[],sourceParsed?:readonly boolean[]):ReadableEvents|null{
  if(!suite)return null;
  const records=splitEvents(sample,'single-line',MAX_EVENTS+1);
  if(records.length<2||records.length>MAX_EVENTS||records.length!==suite.events.length)return null;
  // sourceParsed: the verdict of the server analysis for each event, given with the automatic draft.
  if(sourceParsed&&sourceParsed.length!==records.length)return null;
  const kept:string[]=[];
  const excluded=new Map<string,ExcludedEvents>();
  records.forEach((record,index)=>{
    const verdict=String(suite.events[index]!.parseStatus);
    const accepted=!sourceParsed||(sourceParsed[index]===true&&scan[index]?.status==='RECOGNIZED');
    if(verdict==='FULL'&&accepted){kept.push(record.raw);return;}
    const kind=excludedKind(scan[index],verdict);
    const group=excluded.get(kind)??{kind,count:0,events:[]};
    group.count+=1;group.events.push(index+1);
    excluded.set(kind,group);
  });
  if(kept.length===0||kept.length===records.length)return null;
  return {source:kept.join('\n'),count:kept.length,total:records.length,excluded:[...excluded.values()]};
}

/** "1 × unrecognized format, 2 × delimited record without column names" */
export function describeExcluded(excluded:readonly ExcludedEvents[]):string{
  return excluded.map(group=>group.count+' × '+group.kind).join(', ');
}
