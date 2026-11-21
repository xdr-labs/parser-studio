import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

function suite(...fields:Record<string,unknown>[]):SuiteResult{
  return {events:fields.map(value=>({fields:value}))} as unknown as SuiteResult;
}
function candidateRead(format:string,target:string,...fields:Record<string,unknown>[]){
  const read={events:fields.map(value=>({fields:value,effectiveFormat:format}))} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(read,[]).filter(item=>item.target===target)[0];
}
function candidate(target:string,...fields:Record<string,unknown>[]){
  const found=suggestNormalizationCandidatesFromSuite(suite(...fields),[]).filter(item=>item.target===target);
  expect(found.length,'candidates for '+target).toBeLessThanOrEqual(1);
  return found[0];
}
const traffic={srcip:'10.1.10.25',dstip:'142.250.196.14',srcport:51544,dstport:443,proto:6,action:'accept'};
const web={srcip:'10.1.10.31',dstip:'198.51.100.80',srcport:50211,dstport:80,proto:6,url:'http://bad.example.net/a'};
const system={srcip:'10.1.10.2',dstip:'10.1.10.1',logdesc:'Admin login successful'};

describe('a source named as its official Stellar field in a sample of several record families',()=>{
  it('is approved although some record families do not carry it',()=>{
    for(const target of ['srcport','dstport','url','proto'])
      expect(candidate(target,traffic,web,system),target).toMatchObject({source:target,confidence:'HIGH',safeForBulk:true});
    expect(candidate('url',traffic,web,system)).toMatchObject({observed:1,total:3});
  });

  it('is approved inside a container as well (generic.kv.dstport)',()=>{
    const wrap=(kv:Record<string,unknown>)=>({generic:{kv}});
    expect(candidateRead('generic_structural','dstport',wrap(traffic),wrap(web),wrap(system)))
      .toMatchObject({source:'generic.kv.dstport',confidence:'HIGH',safeForBulk:true});
    // The same path in a JSON log is an object of the log, and a path alone does not say which it is.
    expect(candidateRead('json','dstport',wrap(traffic),wrap(web),wrap(system))).toMatchObject({confidence:'REVIEW'});
    expect(candidate('dstport',wrap(traffic),wrap(web),wrap(system))).toMatchObject({confidence:'REVIEW'});
  });

  it('stays a review proposal when one of its values does not fit the field',()=>{
    expect(candidate('dstport',traffic,{...web,dstport:'http'},system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',traffic,{...web,dstport:70000},system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });

  it('never approves a port beside a protocol that is not TCP or UDP',()=>{
    const icmp={srcip:'10.1.10.9',dstip:'10.1.10.1',srcport:8,dstport:0,proto:1};
    expect(candidate('srcport',traffic,icmp,system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',traffic,icmp,system)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });

  it('never approves a translated port whatever its coverage',()=>{
    expect(candidate('srcport',{nat:{srcport:40000},proto:6},system)).toBeUndefined();
  });

  it('keeps a reviewed abbreviation a review proposal when a record family lacks it',()=>{
    const abbreviated={src:'10.1.10.25',dst:'142.250.196.14',dpt:443,spt:51544,proto:6};
    for(const target of ['srcip','dstip','srcport','dstport'])
      expect(candidate(target,abbreviated,{logdesc:'Admin login successful'}),target)
        .toMatchObject({confidence:'REVIEW',safeForBulk:false});
    // Present in every event, the same abbreviations are approved as before.
    for(const target of ['srcip','dstip','srcport','dstport'])
      expect(candidate(target,abbreviated,{...abbreviated,src:'10.1.10.26'}),target).toMatchObject({confidence:'HIGH'});
  });
});

describe('Zeek conn.log endpoint columns',()=>{
  const conn=(overrides:Record<string,unknown>={})=>({ts:1731719701.123456,uid:'CHhAvVGS1DHFjwGM9',
    'id.orig_h':'10.1.10.25','id.orig_p':51544,'id.resp_h':'142.250.196.14','id.resp_p':443,proto:'tcp',
    service:'ssl',conn_state:'SF',...overrides});

  it('maps originator and responder to source and destination',()=>{
    const events=[conn(),conn({'id.orig_h':'203.0.113.77','id.orig_p':40022,'id.resp_h':'10.1.10.9','id.resp_p':22,proto:'udp'})];
    expect(candidate('srcip',...events)).toMatchObject({source:'id.orig_h',confidence:'HIGH'});
    expect(candidate('dstip',...events)).toMatchObject({source:'id.resp_h',confidence:'HIGH'});
    expect(candidate('srcport',...events)).toMatchObject({source:'id.orig_p',confidence:'HIGH'});
    expect(candidate('dstport',...events)).toMatchObject({source:'id.resp_p',confidence:'HIGH'});
  });

  it('does not take the ICMP type and code columns for ports',()=>{
    const events=[conn(),conn({proto:'icmp','id.orig_p':8,'id.resp_p':0})];
    expect(candidate('srcport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('srcip',...events)).toMatchObject({confidence:'HIGH'});
  });
});

describe('a source field called proto',()=>{
  it('is the protocol name when it holds documented protocol names',()=>{
    expect(candidate('proto_name',{proto:'tcp'},{proto:'UDP'})).toMatchObject({source:'proto',confidence:'HIGH'});
    expect(candidate('proto',{proto:'tcp'},{proto:'UDP'})).toBeUndefined();
  });
  it('is the protocol number when it holds numbers',()=>{
    expect(candidate('proto',{proto:6},{proto:'17'})).toMatchObject({source:'proto',confidence:'HIGH'});
    expect(candidate('proto_name',{proto:6},{proto:'17'})).toBeUndefined();
  });
  it('is neither when it holds an application label or a mix',()=>{
    expect(candidate('proto',{proto:'https'},{proto:'ssh'})).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('proto_name',{proto:'https'},{proto:'ssh'})).toBeUndefined();
    expect(candidate('proto',{proto:'tcp'},{proto:6})).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });
});

describe('official names whose meaning differs between vendors keep the full-coverage rule',()=>{
  it('does not approve a sparse severity, type-like or hash field by its name alone',()=>{
    const alarm={srcip:'10.0.1.2',dstip:'81.2.69.192',severity:4,md5:'69630e4574ec6798239b091cda43dca0',path:'/eicar.com.txt'};
    const flow={srcip:'10.0.1.3',dstip:'81.2.69.193'};
    for(const target of ['severity','md5','path']){
      const found=candidate(target,alarm,flow);
      if(found)expect(found,target).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    }
  });
});

describe('Junos structured data read with underscore names',()=>{
  const flow=(overrides:Record<string,unknown>={})=>({junos_sd:{source_address:'10.0.0.1',source_port:'37233',
    destination_address:'67.43.156.13',destination_port:'161',protocol_id:'17',icmp_type:'0',...overrides}});
  it('maps the addresses and the protocol number like the hyphenated spelling',()=>{
    const events=[flow(),flow({source_address:'10.0.0.2',protocol_id:'6'})];
    expect(candidate('srcip',...events)).toMatchObject({source:'junos_sd.source_address',confidence:'HIGH'});
    expect(candidate('dstip',...events)).toMatchObject({source:'junos_sd.destination_address',confidence:'HIGH'});
    expect(candidate('proto',...events)).toMatchObject({source:'junos_sd.protocol_id',confidence:'HIGH'});
  });
  it('does not take a zero-filled icmp_type of a TCP or UDP session for an ICMP type',()=>{
    expect(candidate('icmp_type',flow(),flow({protocol_id:'6'}))).toBeUndefined();
    // On ICMP sessions the same field is the ICMP type.
    expect(candidate('icmp_type',flow({protocol_id:'1',icmp_type:'8'}),flow({protocol_id:'1',icmp_type:'0'})))
      .toMatchObject({source:'junos_sd.icmp_type',confidence:'HIGH'});
  });
});

// Found by the independent audit of 2026-11-21 (F3-F6, F9). Each of these was approved by the first version of
// the sparse rule; none of them may be.
describe('what the sparse rule must not approve',()=>{
  const system={logdesc:'Admin login successful'};
  const review=(target:string,...events:Record<string,unknown>[])=>{
    const found=candidate(target,...events);
    if(found)expect(found,target).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  };
  it('a port of an ICMP record whose protocol field has another name, another container, or is missing',()=>{
    const tcp=(name:string)=>({srcip:'10.0.0.1',dstip:'93.184.216.34',[name]:6,srcport:51234,dstport:443});
    for(const name of ['ipproto','ip_proto','l4proto','protocol_name','protocol_id']){
      const icmp={srcip:'10.0.0.1',dstip:'8.8.8.8',[name]:name==='protocol_name'?'icmp':1,srcport:8,dstport:0};
      review('srcport',tcp(name),icmp,system);
      review('dstport',tcp(name),icmp,system);
    }
    review('srcport',{srcport:8,dstport:0},system);
    review('srcport',{flow:{srcport:8},net:{proto:'icmp'}},system);
    // FortiGate writes the translated source port as transport=<port>: that field is not protocol evidence, and
    // the ports of such a record are still approved through its proto.
    expect(candidate('srcport',{srcport:51544,dstport:443,proto:6,transport:51544},system)).toMatchObject({confidence:'HIGH'});
    // With TCP or UDP named by every record that has the port, the approval stands.
    expect(candidate('srcport',tcp('ipproto'),{...tcp('ipproto'),ipproto:17},system)).toMatchObject({confidence:'HIGH'});
  });
  it('an explicit port label that only some events carry',()=>{
    review('srcport',{'source-port':'12','destination-port':'2048','protocol-id':'1'},system);
    review('srcport',{'source-port':'51234','destination-port':'443','protocol-id':'6'},system);
  });
  it('Zeek id.orig_p and id.resp_p without a TCP or UDP proto (weird.log: ICMP type and code)',()=>{
    const weird={ts:1763719200.1,'id.orig_h':'192.168.1.10','id.orig_p':8,'id.resp_h':'8.8.8.8','id.resp_p':0,name:'bad_ICMP_checksum'};
    review('srcport',weird,{...weird,'id.orig_p':51234,'id.resp_p':443,name:'data_before_established'});
    review('dstport',weird,{...weird,'id.orig_p':51234,'id.resp_p':443,name:'data_before_established'});
  });
  it('a translated or outer endpoint inside a nested object',()=>{
    for(const container of ['xlate','nat','outer','tunnel']){
      const nested={client_addr:'10.0.0.1',[container]:{srcip:'203.0.113.5',srcport:40002,dstip:'93.184.216.34',dstport:443},proto:6};
      for(const target of ['srcip','dstip','srcport','dstport'])review(target,nested,system);
    }
  });
  it('a field called url whose value is not a URL',()=>{
    review('url',{url:'http://example.com/a'},{url:'category-db-2026.11'},system);
    for(const value of ['update-server-list','10','Malicious Websites'])review('url',{url:value},system);
    expect(candidate('url',{url:'http://example.com/a'},{url:'/index.html'},system)).toMatchObject({confidence:'HIGH'});
  });
});

// Re-audit of 2026-11-21 (N2, N3, N4).
describe('guards of the sparse rule that the re-audit found incomplete',()=>{
  const system={logdesc:'Admin login successful'};
  it('does not take a JSON object called fields, kv or body for a reader container',()=>{
    for(const name of ['fields','kv','body']){
      const nat={client_addr:'10.0.0.1',proto:6,[name]:{srcip:'203.0.113.5',srcport:40002,dstip:'93.184.216.34',dstport:443}};
      for(const target of ['srcip','dstip','srcport','dstport'])
        expect(candidateRead('json',target,nat,system)?.confidence??'REVIEW',name+'.'+target).toBe('REVIEW');
    }
    const deep={xlate:{fields:{srcip:'203.0.113.5',srcport:40002}},proto:6};
    expect(candidateRead('json','srcip',deep,system)?.confidence??'REVIEW').toBe('REVIEW');
    expect(candidateRead('generic_structural','srcip',deep,system)?.confidence??'REVIEW').toBe('REVIEW');
  });
  it('reads protocol evidence in the object that holds the port, in the same event',()=>{
    const nested=(port:number,inner:Record<string,unknown>)=>({proto:6,body:{srcport:port,dstport:0,...inner}});
    expect(candidateRead('syslog_rfc3164','srcport',nested(8,{kind:'icmp-echo'}),system)?.confidence??'REVIEW').toBe('REVIEW');
    expect(candidateRead('syslog_rfc3164','srcport',nested(51234,{proto:'tcp'}),system)).toMatchObject({confidence:'HIGH'});
    expect(candidate('srcport',{srcport:51234,proto:6},{srcport:8},system)).toMatchObject({confidence:'REVIEW'});
  });
  it('does not count a placeholder as coverage',()=>{
    const events=[{srcport:51234,dstport:443,service:'HTTPS'},{srcport:8,dstport:0,service:'PING'},
      {srcport:'-',dstport:'-',service:'-'}];
    expect(candidate('srcport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
    expect(candidate('dstport',...events)).toMatchObject({confidence:'REVIEW',safeForBulk:false});
  });
  it('sees a protocol field whose name is written in another case',()=>{
    const tcp={SrcIP:'10.0.0.1',Protocol:'TCP',SrcPort:51234,DstPort:443};
    expect(candidate('srcport',tcp,{...tcp,Protocol:'ICMP',SrcPort:8,DstPort:0})).toMatchObject({confidence:'REVIEW'});
    expect(candidate('srcport',tcp,{...tcp,Protocol:'udp'})).toMatchObject({confidence:'HIGH'});
  });
  it('pins every protocol field name with a positive and a negative record',()=>{
    for(const name of ['protocol-id','protocol_id','protocol','proto','proto_name','protocol_name','ipproto','ip_proto','l4proto']){
      expect(candidate('srcport',{srcport:51234,[name]:'tcp'},system),name).toMatchObject({confidence:'HIGH'});
      expect(candidate('srcport',{srcport:8,[name]:'icmp'},system),name).toMatchObject({confidence:'REVIEW'});
    }
  });
  it('never approves a sparse endpoint under a translated segment of a reader container',()=>{
    const read={generic:{kv:{proto:6}},nat:{kv:{srcip:'203.0.113.5',srcport:40002,proto:6}}};
    expect(candidateRead('generic_structural','srcip',read,{generic:{kv:{note:'x'}}})?.confidence??'REVIEW').toBe('REVIEW');
  });
});

// Independent audit of 2026-11-21, seen outside the diff (same on main): Zeek http.log `host` is the HTTP Host header.
describe('the requested host of an HTTP request record is not the official hostname',()=>{
  const http=(overrides:Record<string,unknown>={})=>({ts:1763719200.1,uid:'CmES5u32sYpV7JYN','id.orig_h':'192.168.1.10',
    'id.orig_p':51234,'id.resp_h':'93.184.216.34','id.resp_p':80,method:'GET',host:'example.com',uri:'/index.html',
    user_agent:'curl/8.5.0',status_code:200,...overrides});
  it('does not propose hostname for host beside a method and a resource, agent or status',()=>{
    expect(candidate('hostname',http(),http({host:'example.org',uri:'/a'}))).toBeUndefined();
    expect(candidate('hostname',{request_method:'POST',host:'shop.example.com',request_uri:'/cart'})).toBeUndefined();
    expect(candidate('hostname',{Method:'GET',host:'example.com',URI:'/'})).toBeUndefined();
    expect(candidate('hostname',{http:{method:'GET',host:'example.com',url:'/x'}})).toBeUndefined();
  });
  it('keeps hostname for the host that a record is about',()=>{
    expect(candidate('hostname',{host:'fw01',msg:'link up'},{host:'fw02',msg:'link down'})).toMatchObject({source:'host',confidence:'HIGH'});
    // A method alone, or a resource alone, does not make the record an HTTP request.
    expect(candidate('hostname',{host:'fw01',method:'https'},{host:'fw02',method:'ssh'})).toMatchObject({confidence:'HIGH'});
    expect(candidate('hostname',{host:'fw01',url:'/admin'},{host:'fw02',url:'/login'})).toMatchObject({confidence:'HIGH'});
    // Another object of the same event may be an HTTP request; the host beside it is not.
    expect(candidate('hostname',{host:'proxy01',request:{method:'GET',uri:'/'}})).toMatchObject({source:'host',confidence:'HIGH'});
  });
});
