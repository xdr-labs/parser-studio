import {expect,test} from '@playwright/test';

const first='{"event":"allow","user":"김민수","src_ip":"192.0.2.10"}';
const second='{"event":"deny","user":"홍길동","src_ip":"198.51.100.20"}';

test('a full local history with rejected rows can recover space without losing verified versions',async({page})=>{
  test.setTimeout(90_000);
  const outbound:string[]=[];
  page.on('request',request=>{
    if(request.method()!=='GET'&&request.url().includes('/api/'))
      outbound.push(request.url());
  });
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(first);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Verified source V1');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText('Verified source V1');

  // Populate user-browser IndexedDB with invalid snapshots to reproduce the
  // genuine bounded 30-slot capacity failure, without involving any server.
  await page.evaluate(async()=>{
    const db=await new Promise<IDBDatabase>((resolve,reject)=>{
      const request=indexedDB.open('parser-studio-user-experiments-v1',1);
      request.onsuccess=()=>resolve(request.result);
      request.onerror=()=>reject(request.error);
    });
    try{
      await new Promise<void>((resolve,reject)=>{
        const tx=db.transaction('versions','readwrite');
        const store=tx.objectStore('versions');
        for(let index=0;index<29;index++){
          store.add({id:index===28?'legacy-invalid-row':crypto.randomUUID(),
            contract:'parser-studio.browser-version.v1',
            label:`Invalid ${index}`,createdAt:new Date().toISOString(),
            datasetName:'Synthetic',source:'internal synthetic only',draft:{},
            sha256:'0'.repeat(64)});
        }
        tx.oncomplete=()=>resolve();
        tx.onerror=()=>reject(tx.error);
        tx.onabort=()=>reject(tx.error);
      });
    }finally{db.close()}
  });
  await page.reload();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const recovered=page.getByLabel('Local Versions workspace');
  await expect(recovered).toContainText('29 corrupt or unverified local version(s)');
  await expect(recovered.getByLabel('Saved local versions')).toContainText('Verified source V1');
  await source.fill(second);
  await recovered.getByLabel('Local version name').fill('New source V2');
  await recovered.getByRole('button',{name:'Save Version'}).click();
  await expect(recovered.getByRole('status')).toContainText('Local history is full');
  let approved=false;
  page.on('dialog',dialog=>approved?dialog.accept():dialog.dismiss());
  await recovered.getByRole('button',{name:'Delete unverified local versions'}).click();
  // Dismissing the destructive confirmation must leave all rejected records
  // and the verified saved revision in place, without changing current logs.
  await expect(recovered).toContainText('29 corrupt or unverified local version(s)');
  await expect(source).toHaveValue(second);
  approved=true;
  await recovered.getByRole('button',{name:'Delete unverified local versions'}).click();
  await expect(recovered.getByLabel('Saved local versions')).toContainText('Verified source V1');
  await expect(recovered).not.toContainText('29 corrupt or unverified local version(s)');
  await recovered.getByRole('button',{name:'Save Version'}).click();
  await expect(recovered.getByLabel('Saved local versions')).toContainText('New source V2');
  await recovered.getByText('Verified source V1',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(source).toHaveValue(first);
  expect(outbound).toEqual([]);
});
