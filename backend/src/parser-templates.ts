/**
 * Conservative, public synthetic starter templates for the portable schema.
 * They are not vendor parser samples, native fixtures or target-approved
 * imports. Users still need to review mappings against their own events.
 */
import type {ParserProject} from "./types.js";
import {validateProject} from "./validate.js";

export class ParserTemplateError extends Error{
  constructor(readonly code:string){super(code);this.name="ParserTemplateError";}
}
const denied=(code:string):never=>{throw new ParserTemplateError(code);};
export type ParserTemplateId="json"|"kv"|"csv"|"rfc5424"|"cef"|"leef";
export type ParserTemplateInfo={
  id:ParserTemplateId;
  title:string;
  description:string;
  format:ParserProject["extraction"]["format"];
  minPort:number;
  requiresNativeVerification:true;
  targetVerified:false;
};
export type ParserTemplateOptions={
  projectId:string;
  slug:string;
  revision:number;
  port:number;
  protocols:("udp"|"tcp")[];
};
const CATALOG:readonly ParserTemplateInfo[]=[
  {id:"json",title:"JSON event",description:"One JSON event per message",
    format:"json",minPort:1024,requiresNativeVerification:true,targetVerified:false},
  {id:"kv",title:"Key/value",description:"Flat key=value messages",
    format:"kv",minPort:1024,requiresNativeVerification:true,targetVerified:false},
  {id:"csv",title:"CSV rows",description:"Three-column synthetic starter rows",
    format:"csv",minPort:1024,requiresNativeVerification:true,targetVerified:false},
  {id:"rfc5424",title:"RFC5424 Syslog",description:"RFC5424 envelope with key/value body",
    format:"syslog_rfc5424",minPort:6800,requiresNativeVerification:true,targetVerified:false},
  {id:"cef",title:"CEF events",description:"CEF header and key/value extension",
    format:"cef",minPort:1024,requiresNativeVerification:true,targetVerified:false},
  {id:"leef",title:"LEEF events",description:"LEEF header and key/value extension",
    format:"leef",minPort:1024,requiresNativeVerification:true,targetVerified:false},
];
export function listParserTemplates():ParserTemplateInfo[]{
  return CATALOG.map(template=>({...template}));
}
export function instantiateParserTemplate(id:string,
  options:ParserTemplateOptions):ParserProject{
  const template=CATALOG.find(x=>x.id===id);
  if(!template)return denied("TEMPLATE_NOT_FOUND");
  if(!options||typeof options!=="object"||Array.isArray(options)||
     Object.keys(options).sort().join(",")!==
       "port,projectId,protocols,revision,slug")
    denied("TEMPLATE_OPTIONS_INVALID");
  const candidate:ParserProject={
    schemaRevision:"0.1",
    projectId:options.projectId,
    revision:options.revision,
    slug:options.slug,
    vendor:"Synthetic",
    product:template.title+" Starter",
    sourceCategory:"other",
    receiver:{
      protocols:Array.isArray(options.protocols)?[...options.protocols]:options.protocols,
      port:options.port,bindAddress:"0.0.0.0",
      messageLengthLimit:16384,tcpFraming:"line",
    },
    extraction:template.format==="csv"?
      {format:"csv",csvColumns:["time","action","src_ip"],csvDelimiter:","}:
      template.format==="syslog_rfc5424"?
      {format:"syslog_rfc5424",syslogBodyFormat:"kv"}:
      {format:template.format},
    normalization:{
      msgOriginSource:options.slug,
      msgClass:options.slug,
      msgOriginCategory:"other",
      ignoreValues:["","N/A","-"],
      // This simple mapped string is a starting suggestion only. Never
      // claim the source event contains it until the user tests actual logs.
      topFields:{action:{normalized_name:"action",data_type:"string"}},
      nsFields:{},vendorFields:{},
    },
    classification:{defaultIndex:"syslog",rules:[]},
  };
  if(!Number.isInteger(options.port)||options.port<template.minPort||
     !validateProject(candidate).ok)denied("TEMPLATE_PROJECT_INVALID");
  return candidate;
}
