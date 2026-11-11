import assert from "node:assert/strict";
import test from "node:test";
import {analyzeRuby24RegexCost,RUBY24_REGEX_MAX_INPUT_BYTES} from "../src/ruby24-regex-cost.js";
import {createPortableRegex} from "../src/portable-regex.js";

const ftd=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[\d.]+)/(?<srcport>\d+) \([\d.]+/\d+\) to \w+:(?<dstip>[\d.]+)/(?<dstport>\d+) \([\d.]+/\d+\)$`;

/** Patterns a real operator writes: anchored, delimiter-separated, one scan loop. */
const ACCEPTED=[
  ftd,
  String.raw`^(?<ts>\w+ \d+ [\d:]+) (?<host>\S+) (?<proc>[\w-]+)\[(?<pid>\d+)\]: (?<msg>.*)$`,
  String.raw`^src=(?<src>[\d.]+) dst=(?<dst>[\d.]+) proto=(?<proto>\w+)$`,
  String.raw`^(?<action>ACCEPT|DENY),(?<srcip>\d+\.\d+\.\d+\.\d+),(?<port>\d{1,5})$`,
  String.raw`^(?<a>[^,]*),(?<b>[^,]*),(?<c>[^,]*)$`,
];

/** Each entry must be refused for its documented reason. */
const REJECTED:Array<[string,string]>=[
  [String.raw`(?<digits>\d+)`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^(?<a>.*),(?<b>.*)$`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^.*a(?<x>[a-z]+)1$`,"REGEX_POLYNOMIAL_AMBIGUITY"],
  [String.raw`^(?<a>a|ab)(?<b>c|bcd)$`,"REGEX_NONDETERMINISTIC_CHOICE"],
];

test("operator-style anchored patterns are classified as constant-ambiguity",()=>{
  for(const pattern of ACCEPTED){
    const result=analyzeRuby24RegexCost(pattern);
    assert.equal(result.ok,true,pattern+" => "+JSON.stringify(result));
    if(result.ok)assert.equal(result.anchored,true);
  }
});

test("quadratic, exponential and ambiguous-choice patterns are refused with a precise reason",()=>{
  for(const [pattern,reason] of REJECTED){
    const result=analyzeRuby24RegexCost(pattern);
    assert.equal(result.ok,false,pattern);
    if(!result.ok)assert.equal(result.reason,reason,pattern);
  }
});

test("non-portable syntax is refused before any cost analysis",()=>{
  assert.equal(analyzeRuby24RegexCost(String.raw`^(?<a>a+)\1$`).ok,false);
  assert.equal(analyzeRuby24RegexCost(String.raw`^(?<a>\h+)$`).ok,false);
});

test("accepted patterns stay fast on adversarial input under an independent backtracking engine",()=>{
  const n=RUBY24_REGEX_MAX_INPUT_BYTES;
  const attacks=["a".repeat(n),"1".repeat(n),
    "%FTD-6-1: Built inbound TCP connection 1 for a:1.1/1 ".repeat(Math.floor(n/52)),
    ",".repeat(n),"a=1 ".repeat(n/4),"x ".repeat(n/2),"1.".repeat(n/2)];
  for(const pattern of ACCEPTED){
    const regex=createPortableRegex(pattern);
    for(const input of attacks){
      const started=process.hrtime.bigint();
      regex.exec(input);
      const millis=Number(process.hrtime.bigint()-started)/1e6;
      assert.ok(millis<250,`${millis.toFixed(1)}ms for ${pattern.slice(0,40)} on ${input.slice(0,12)}`);
    }
  }
});
