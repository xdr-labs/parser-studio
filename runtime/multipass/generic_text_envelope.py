"""Bounded, vendor-neutral textual log-header recovery.

Recognizes only exact anchored header layouts. The remaining free-text message
is preserved byte-for-byte, while unknown message semantics remain REVIEW.
This must never be interpreted as a compiler-ready parser or official field map.
"""
from __future__ import annotations

import re
from source_parse import SourceEvent, _close, _span

MAX_LINE = 8192
LEVELS = frozenset({'TRACE','DEBUG','INFO','NOTICE','WARN','WARNING','ERROR','FATAL','CRITICAL'})
MONTH_DAYS=(0,31,29,31,30,31,30,31,31,30,31,30,31)
MONTHS={'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
        'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

PROXIFIER = re.compile(
 r'^\[(?P<monthday>\d{2}\.\d{2}) (?P<clock>\d{2}:\d{2}:\d{2})\] '
 r'(?P<process>[^\r\n\[\]]{1,128}?) - (?P<message>[^\r\n]+)$'
)
SIX_DIGIT = re.compile(
 r'^(?P<datecode>\d{6}) (?P<clockcode>\d{6}) (?P<pid>\d{1,8}) '
 r'(?P<severity>TRACE|DEBUG|INFO|WARN|ERROR|FATAL) '
 r'(?P<component>[A-Za-z_][A-Za-z0-9_.$/-]{0,159}): (?P<message>[^\r\n]+)$'
)
APACHE_BRACKET = re.compile(
 r'^\[(?P<weekday>Mon|Tue|Wed|Thu|Fri|Sat|Sun) '
 r'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
 r'(?P<day>\d{2}) (?P<clock>\d{2}:\d{2}:\d{2}) (?P<year>\d{4})\] '
 r'\[(?P<severity>[A-Za-z]{2,16})\] (?P<message>[^\r\n]+)$'
)
JAVA_STYLE = re.compile(
 r'^(?P<date>\d{4}-\d{2}-\d{2}) (?P<clock>\d{2}:\d{2}:\d{2}),(?P<millis>\d{3})'
 r' - (?P<severity>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+'
 r'\[(?P<thread>[^\r\n]{1,255})\] - (?P<message>[^\r\n]+)$'
)
ANDROID = re.compile(
 r'^(?P<monthday>\d{2}-\d{2}) (?P<clock>\d{2}:\d{2}:\d{2})\.(?P<millis>\d{3})'
 r'\s+(?P<pid>\d{1,8})\s+(?P<tid>\d{1,8}) '
 r'(?P<severity>[VDIWEAF]) (?P<component>[A-Za-z_][A-Za-z0-9_.-]{0,127}): '
 r'(?P<message>[^\r\n]+)$'
)

def _valid_clock(value:str)->bool:
 if len(value)!=8 or value[2]!=':' or value[5]!=':':return False
 parts=value.split(':')
 return all(x.isdigit() for x in parts) and 0<=int(parts[0])<=23 and 0<=int(parts[1])<=59 and 0<=int(parts[2])<=60

def _valid_monthday(value:str,sep:str)->bool:
 try:m,d=map(int,value.split(sep))
 except (ValueError,AttributeError):return False
 return 1<=m<=12 and 1<=d<=MONTH_DAYS[m]

def _valid_date(value:str)->bool:
 try:y,m,d=map(int,value.split('-'))
 except ValueError:return False
 if not (1970<=y<=9999 and 1<=m<=12):return False
 max_day=29 if m==2 and (y%4==0 and (y%100!=0 or y%400==0)) else (28 if m==2 else MONTH_DAYS[m])
 return 1<=d<=max_day

def _matches(name:str,match:re.Match)->bool:
 parts=match.groupdict()
 if name=='BRACKET_PROCESS':
  return _valid_monthday(parts['monthday'],'.') and _valid_clock(parts['clock']) and parts['process'].strip()==parts['process']
 if name=='DATECODE_LEVEL':
  date=parts['datecode'];t=parts['clockcode']
  return (_valid_monthday(date[2:4]+'-'+date[4:6],'-') and
          int(t[:2])<=23 and int(t[2:4])<=59 and int(t[4:6])<=60)
 if name=='APACHE_BRACKET':
  return (_valid_clock(parts['clock']) and parts['severity'].upper() in LEVELS and
   1<=int(parts['day'])<=MONTH_DAYS[MONTHS[parts['month']]] and
   1970<=int(parts['year'])<=9999)
 if name=='DATE_TIME_LEVEL_THREAD':
  return _valid_date(parts['date']) and _valid_clock(parts['clock'])
 if name=='LOGCAT':
  return _valid_monthday(parts['monthday'],'-') and _valid_clock(parts['clock'])
 return False

def recover_textual_header(raw:str)->SourceEvent|None:
 if not isinstance(raw,str) or not raw or len(raw.encode('utf8'))>MAX_LINE or any(x in raw for x in ('\x00','\r','\n')):
  return None
 for name,pattern in (
  ('BRACKET_PROCESS',PROXIFIER),
  ('DATECODE_LEVEL',SIX_DIGIT),
  ('APACHE_BRACKET',APACHE_BRACKET),
  ('DATE_TIME_LEVEL_THREAD',JAVA_STYLE),
  ('LOGCAT',ANDROID),
 ):
  m=pattern.fullmatch(raw)
  if m is None or not _matches(name,m):continue
  fields={k:v for k,v in m.groupdict().items() if k!='message'}
  header={'datecode','monthday','month','day','weekday','year','date','clock','clockcode','millis','pid','tid','severity','component','thread','process'}
  if not set(fields).issubset(header):raise AssertionError('UNEXPECTED_HEADER_KEY')
  data=SourceEvent(raw,syntax='GENERIC_TEXT_ENVELOPE_'+name,
    vendor_fields={'text_header':fields,'body':{'message':m.group('message')}},
    primitive_fields=len(fields)+1,
    issues=['FREE_TEXT_FIELD_ROLES_NEED_REVIEW'],
    covered=[(0,len(raw))])
  data.value_spans=[
    _span(raw,'text_header.'+key,*m.span(key)) for key in fields
  ]+[_span(raw,'body.message',*m.span('message'))]
  return _close(data)
 return None
