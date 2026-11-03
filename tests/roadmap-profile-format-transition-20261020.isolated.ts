import {test,expect,type Page} from '@playwright/test';
import {readFileSync} from 'node:fs';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/roadmap-syslog-prefix-kv-20261020.json',import.meta.url),'utf8')) as {positive:Array<{raw:string}>};

async function savedVersions(page:Page){
  return page.evaluate(async()=>{
    const db=await new Promise<IDBDatabase>((resolve,reject)=>{
      const request=indexedDB.open('parser-studio-user-experiments-v1',1);
      request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
    });
    try{
      return await new Promise<Array<{label:string;source:string;draft:{format:string;genericStructuralProfile?:string;csvColumns:string}}>>((resolve,reject)=>{
        const tx=db.transaction('versions','readonly');
        const request=tx.objectStore('versions').getAll();
        request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
      });
    }finally{db.close();}
  });
}

test('a novice switches a generic profile to Zeek CSV and saves and reviews the new parser',async({page},info)=>{
  test.setTimeout(120000);
  const original=fixture.positive[0]!.raw;
  const rows='allow\t192.0.2.10\t443\ndeny\t198.51.100.20\t8443';
  const zeek='#separator \\x09\n#fields\taction\tsrc_ip\tdst_port\n'+rows;
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(original);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event structurally parsed',{timeout:30000});
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Reviewed generic profile');
  await history.getByRole('button',{name:'Save Version',exact:true}).click();
  await expect(history).toContainText('1/30 saved');
  const previous=(await savedVersions(page)).find(version=>version.label==='Reviewed generic profile');
  expect(previous?.source).toBe(original);
  expect(previous?.draft).toMatchObject({format:'generic_structural',genericStructuralProfile:'syslog_prefix_kv'});

  await source.fill(zeek);
  await page.getByRole('button',{name:'Prepare Zeek data rows and field names',exact:true}).click();
  await expect(source).toHaveValue(rows);
  await history.getByLabel('Local version name').fill('Reviewed Zeek CSV');
  await history.getByRole('button',{name:'Save Version',exact:true}).click();
  await expect(history).toContainText('2/30 saved');
  await expect(history.getByRole('status')).toContainText('Saved in this browser only');
  const saved=(await savedVersions(page)).find(version=>version.label==='Reviewed Zeek CSV');
  expect(saved?.source).toBe(rows);
  expect(saved?.draft).toMatchObject({format:'csv',csvColumns:'action,src_ip,dst_port'});
  expect(saved?.draft).not.toHaveProperty('genericStructuralProfile');

  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:30000});
  await expect(page.getByLabel('Reviewed CSV column names')).toHaveValue('action,src_ip,dst_port');
  await page.getByRole('button',{name:'I Confirm These CSV Column Names',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  const fields=page.getByLabel('Review Fields stage');
  await expect(fields).toBeVisible({timeout:30000});
  await expect(fields.getByLabel('Browser-only event inspector')).toContainText('192.0.2.10');
  await expect(fields.getByLabel('Browser-only event inspector')).not.toContainText('%FTD-4-430002');
  await page.screenshot({path:info.outputPath('generic-to-zeek-csv-reviewed.png'),fullPage:true});
  await info.attach('format-transition-snapshots',{contentType:'application/json',body:JSON.stringify({previous,saved},null,2)});
});
