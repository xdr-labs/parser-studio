import {test,expect} from './support/downloadSink';
import {spawn} from 'node:child_process';
import {createSocket} from 'node:dgram';
import {createServer} from 'node:net';
import {generatePythonSenderForSample} from './support/pythonSenderJourney';

const synthetic=JSON.stringify({
  timestamp:'2020-10-17T11:12:13Z',src_ip:'192.0.2.10',
  dst_ip:'198.51.100.10',username:'alice',
  email:'alice@example.test',location:'Seoul',action:'allow',
});
type Receipt={text:string;at:number};
async function execute(file:string,port:number,transport:'UDP'|'TCP',count:number,
  approved=true):Promise<{code:number|null;stdout:string;stderr:string}>{
  const child=spawn('python3',[file],{stdio:['pipe','pipe','pipe']});
  let stdout='',stderr='';
  child.stdout.on('data',chunk=>stdout+=chunk.toString());
  child.stderr.on('data',chunk=>stderr+=chunk.toString());
  child.stdin.end(['127.0.0.1',String(port),transport,String(count),approved?'YES':'NO',''].join('\n'));
  const code=await new Promise<number|null>((resolve,reject)=>{
    const timeout=setTimeout(()=>{child.kill();reject(Error('Synthetic test sender did not stop within 15 seconds'));},15000);
    child.once('error',error=>{clearTimeout(timeout);reject(error)});
    child.once('exit',code=>{clearTimeout(timeout);resolve(code)});
  });
  return {code,stdout,stderr};
}
test('user downloads self-contained Python, approves network destination and sends 1 event/s over loopback UDP',async({page})=>{
  const network:string[]=[];
  page.on('request',request=>{
    if(request.url().includes('/api/')&&request.method()!=='GET')network.push(request.url());
  });
  await generatePythonSenderForSample(page,synthetic);
  const writesBeforeSenderDownload=network.length;
  const panel=page.getByRole('group',{name:'Python test sender'});
  await panel.locator('summary').click();
  await expect(panel).toContainText('encoded as base64, not encrypted');
  const downloadPromise=page.waitForEvent('download');
  await panel.getByRole('button',{name:'Download Python Test Sender'}).click();
  const downloaded=await downloadPromise;
  expect(downloaded.suggestedFilename()).toBe('parser_studio_test_sender.py');
  await expect(panel.getByRole('status')).toContainText('No log was transmitted by Parser Studio.');
  expect(network.slice(writesBeforeSenderDownload)).toEqual([]);
  const localFile=await downloaded.path();
  expect(localFile).toBeTruthy();

  const receiver=createSocket('udp4');
  const receipts:Receipt[]=[];
  receiver.on('message',message=>receipts.push({text:message.toString(),at:Date.now()}));
  await new Promise<void>(resolve=>receiver.bind(0,'127.0.0.1',resolve));
  try{
    const port=receiver.address().port;
    const denied=await execute(localFile!,port,'UDP',2,false);
    expect(denied.code).not.toBe(0);
    expect(denied.stdout).toContain('Stopped before sending');
    expect(receipts).toHaveLength(0);

    const completed=await execute(localFile!,port,'UDP',3,true);
    await expect.poll(()=>receipts.length,{timeout:3000}).toBe(3);
    expect(completed.code).toBe(0);
    expect(completed.stderr).toBe('');
    expect(completed.stdout).toContain('attempted 3 of 3 event(s)');
    const parsed=receipts.map(item=>JSON.parse(item.text));
    for(const item of parsed){
      expect(item.action).toBe('allow');
      expect(item.src_ip).toMatch(/^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d+$/);
      expect(item.src_ip).not.toBe('192.0.2.10');
      expect(item.email).toMatch(/^user\d{6}@example\.test$/);
      expect(item.username).toMatch(/^user\d{5}$/);
      expect(['Seoul','Tokyo','London','Toronto','Paris','Singapore']).toContain(item.location);
      expect(Math.abs(Date.now()-Date.parse(item.timestamp))).toBeLessThan(10000);
    }
    expect(receipts[1]!.at-receipts[0]!.at).toBeGreaterThanOrEqual(800);
    expect(receipts[2]!.at-receipts[1]!.at).toBeGreaterThanOrEqual(800);
    expect(parsed[0].email).not.toBe(parsed[1].email);
  }finally{receiver.close();}
});

test('downloaded sender transmits bounded LF-framed TCP messages without third-party dependencies',async({page})=>{
  await generatePythonSenderForSample(page,
    'date=2020-01-01 time=08:00:00 action=deny srcip=192.0.2.10 user=alice');
  const panel=page.getByRole('group',{name:'Python test sender'});
  await panel.locator('summary').click();
  const request=page.waitForEvent('download');
  await panel.getByRole('button',{name:'Download Python Test Sender'}).click();
  const file=await (await request).path();
  expect(file).toBeTruthy();
  const receipts:Receipt[]=[];
  const server=createServer(socket=>{
    let buffer='';
    socket.on('data',chunk=>{
      buffer+=chunk.toString();
      while(buffer.includes('\n')){
        const index=buffer.indexOf('\n');
        receipts.push({text:buffer.slice(0,index),at:Date.now()});
        buffer=buffer.slice(index+1);
      }
    });
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const port=(server.address() as {port:number}).port;
    const finished=await execute(file!,port,'TCP',2);
    expect(finished.code).toBe(0);
    await expect.poll(()=>receipts.length,{timeout:3000}).toBe(2);
    for(const row of receipts){
      expect(row.text).toContain('action=deny');
      expect(row.text).toMatch(/date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2}/);
      expect(row.text).toMatch(/user=user\d{5}/);
    }
    expect(receipts[1]!.at-receipts[0]!.at).toBeGreaterThanOrEqual(800);
  }finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
});
