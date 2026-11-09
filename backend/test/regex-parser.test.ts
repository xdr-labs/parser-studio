import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import test from "node:test";
import {compilePair} from "../src/compiler.js";
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from "../src/parser-recipe-v02.js";
import {validateBoundedRegexPattern,validateProject} from "../src/validate.js";
import {sampleProject} from "./fixture.js";

const sha=(value:string)=>createHash("sha256").update(value,"utf8").digest("hex");
const safePattern=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[\d.]+)/(?<srcport>\d+) \([\d.]+/\d+\) to \w+:(?<dstip>[\d.]+)/(?<dstport>\d+) \([\d.]+/\d+\)$`;

function regexProject(){
  const project=sampleProject();
  project.projectId="draft-regex_firewall";
  project.slug="regex_firewall";
  project.product="FTD";
  project.extraction={format:"regex",pattern:safePattern};
  project.normalization={
    msgOriginSource:"regex_firewall",msgClass:"regex_firewall",msgOriginCategory:"network",ignoreValues:["","N/A","-"],
    topFields:{
      srcip:{normalized_name:"srcip",data_type:"ip"},
      dstip:{normalized_name:"dstip",data_type:"ip"},
      protocol:{normalized_name:"protocol",data_type:"string"},
    },
    nsFields:{
      srcport:{normalized_name:"srcport",data_type:"port"},
      dstport:{normalized_name:"dstport",data_type:"port"},
      event_id:{normalized_name:"log.event_id",data_type:"integer"},
    },
    vendorFields:{},
  };
  project.classification={defaultIndex:"syslog",rules:[]};
  return project;
}

test("bounded named-capture Regex validates and compiles without changing unrelated parser template bytes",()=>{
  assert.equal(validateBoundedRegexPattern(safePattern),null);
  const project=regexProject();
  assert.equal(validateProject(project).ok,true);
  const regexPair=compilePair(project);
  const parser=regexPair.files.find(x=>x.name==="customized_regex_firewall")!;
  assert.match(parser.content,/def parserstudio_regex/);
  assert.match(parser.content,/Regexp.respond_to\?\(:timeout=\)/);
  assert.match(parser.content,/defined\?\(Regexp::TimeoutError\)/);
  assert.match(regexPair.manifest.warnings.join(" "),/Ruby 2\.4\.9.*fails closed/);
  assert.equal(parser.content.includes(safePattern),false,"pattern must stay inside encoded reviewed project metadata");

  const json=sampleProject();
  const baseline=compilePair(json);
  const baselineParser=baseline.files.find(x=>x.name==="customized_sample_firewall")!;
  assert.equal(baselineParser.content.includes("def parserstudio_regex"),false,
    "bounded Regex helper must not change non-Regex artifact bytes");
});

test("Regex ParserRecipe round-trips exactly through the v0.2 compiler subset",()=>{
  const project=regexProject();
  const source=[
    "May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/443 (81.2.69.144/443)",
    "May  5 17:51:18 dev01: %FTD-6-302015: Built inbound UDP connection 112 for net:10.10.10.11/53501 (81.2.69.144/53501) to fw111:192.168.2.3/53 (81.2.69.144/53)",
  ].join("\n");
  const recipe=recipeFromLegacyProject(project,sha(source),2);
  assert.equal(recipe.stages[1]?.op,"parse_regex");
  assert.deepEqual(recipe.stages[1],{op:"parse_regex",pattern:safePattern});
  const checked=validateRecipePair({recipe,legacyProject:project});
  assert.equal(checked.ok,true,JSON.stringify(checked.issues));
  const staged=compileRecipePair({recipe,legacyProject:project});
  const direct=compilePair(project);
  assert.deepEqual(staged.files,direct.files);
  assert.deepEqual(staged.manifest,direct.manifest);
});

test("unsafe or unbounded Regex patterns fail closed before artifact generation",()=>{
  for(const pattern of [
    "(?<value>(a+)+)$",
    String.raw`^(?<value>a+)\1$`,
    "(?<value>(?:a|aa)+)$",
    "a".repeat(257)+"(?<value>b)",
    "^plain text only$",
  ]){
    assert.notEqual(validateBoundedRegexPattern(pattern),null,pattern);
    const project=regexProject();project.extraction={format:"regex",pattern};
    const checked=validateProject(project);
    assert.equal(checked.ok,false,pattern);
    assert.throws(()=>compilePair(project));
  }
});
