/**
 * Cisco ASA 302013 fixture shared by the Ruby 2.4.9 artifact gate and the real
 * Fluentd UDP reception gate. The pattern is authored from Cisco's documented
 * message grammar; raw lines and expected values come from the
 * VENDOR_PUBLISHED_TEXT corpus file, never from generated Ruby.
 */
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

// Cisco ASA 302013 (Built inbound|outbound ...). Pattern authored from Cisco's
// documented message grammar; the raw lines and expected values come from the
// VENDOR_PUBLISHED_TEXT corpus file, never from generated Ruby.
export const ASA_PATTERN=String.raw`^.*%ASA-\d-(?<event_id>\d+): Built (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>\d+) for \w+:(?<src_ip>[\d.]+)/(?<src_port>\d+) \([\d.]+/\d+\) to \w+:(?<dst_ip>[\d.]+)/(?<dst_port>\d+) \((?<dst_mapped_ip>[\d.]+)/\d+\)$`;
export const ASA_CORPUS=(JSON.parse(readFileSync(resolve(import.meta.dirname,'../../evals/golden-corpus/vendor-published-text-cisco-asa.v1.json'),'utf8')) as {
  cases:{id:string;sampleClass:string;rawSample:string;expectedMatch:boolean;expectedFields:Record<string,string>;expectedStellarFields:Record<string,string>}[];
}).cases.map(({id,sampleClass,rawSample,expectedMatch,expectedFields,expectedStellarFields})=>
  ({id,sampleClass,rawSample,expectedMatch,expectedFields,expectedStellarFields}));
export function applyAsaNormalization(project:{normalization:{topFields:unknown;nsFields:unknown;vendorFields:unknown}}):void{
  project.normalization.topFields={
    src_ip:{normalized_name:'srcip',data_type:'ip'},
    dst_ip:{normalized_name:'dstip',data_type:'ip'},
    protocol:{normalized_name:'protocol',data_type:'string'},
  };
  project.normalization.nsFields={
    src_port:{normalized_name:'srcport',data_type:'port'},
    dst_port:{normalized_name:'dstport',data_type:'port'},
    event_id:{normalized_name:'log.event_id',data_type:'integer'},
  };
  project.normalization.vendorFields={};
}
