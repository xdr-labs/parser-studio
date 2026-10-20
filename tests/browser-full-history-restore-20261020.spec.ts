import {test,expect} from '@playwright/test';

const sample=(index:number)=>JSON.stringify({event:index,user:'김민수',action:'allow'});

test('full verified history restores saved working copies without discarding unsaved changes',async({page})=>{
  test.setTimeout(120_000);
  const writes:string[]=[],errors:string[]=[];
  page.on('request',request=>{
    if(request.url().includes('/api/')&&request.method()!=='GET')writes.push(request.url());
  });
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  const source=page.getByLabel('Auto Parser raw logs');
  for(let index=1;index<=30;index++){
    await source.fill(sample(index));
    await history.getByLabel('Local version name').fill('Verified V'+index);
    await history.getByRole('button',{name:'Save Version',exact:true}).click();
    await expect(history).toContainText(index+'/30 saved');
  }
  const restore=(label:string)=>history.getByText(label,{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore',exact:true});
  page.on('dialog',dialog=>dialog.accept());
  // Explicit named saves must still respect the unchanged 30-version limit.
  await history.getByLabel('Local version name').fill('Duplicate named save');
  await history.getByRole('button',{name:'Save Version',exact:true}).click();
  await expect(history.getByRole('status')).toContainText('Local history is full');
  // V30 already protects every byte of the current copy. A full history
  // must not require another identical backup just to restore V1.
  await restore('Verified V1').click();
  await expect(source).toHaveValue(sample(1));
  await expect(history).toContainText('30/30 saved');
  await expect(history.getByLabel('Saved local versions').locator('.local-version-row')).toHaveCount(30);
  await restore('Verified V30').click();
  await expect(source).toHaveValue(sample(30));

  const unsaved=JSON.stringify({event:31,user:'홍길동',action:'deny',note:'Not saved yet'});
  await source.fill(unsaved);
  await restore('Verified V1').click();
  await expect(history.getByRole('status')).toContainText('Local history is full');
  await expect(source).toHaveValue(unsaved);
  await expect(history.getByLabel('Saved local versions').locator('.local-version-row')).toHaveCount(30);

  // Only the user's explicit deletion frees a slot. Restoring now must
  // preserve the unsaved copy first, rather than bypassing that safety gate.
  await history.getByRole('button',{name:'Delete local version Verified V10',exact:true}).click();
  await expect(history).toContainText('29/30 saved');
  await restore('Verified V1').click();
  await expect(source).toHaveValue(sample(1));
  await expect(history).toContainText('30/30 saved');
  const backup=history.getByLabel('Saved local versions').locator('.local-version-row')
    .filter({hasText:'Before restore'});
  await expect(backup).toHaveCount(1);
  await backup.getByRole('button',{name:'Restore',exact:true}).click();
  await expect(source).toHaveValue(unsaved);
  // A stale UI list must not vouch for a checkpoint corrupted in another tab.
  await page.evaluate(async()=>{
    const db=await new Promise<IDBDatabase>((resolve,reject)=>{
      const request=indexedDB.open('parser-studio-user-experiments-v1',1);
      request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
    });
    try{
      await new Promise<void>((resolve,reject)=>{
        const tx=db.transaction('versions','readwrite');
        const cursor=tx.objectStore('versions').openCursor();
        cursor.onsuccess=()=>{
          const row=cursor.result;if(!row)return;
          if(String(row.value.label).startsWith('Before restore'))
            row.update({...row.value,sha256:'0'.repeat(64)});
          row.continue();
        };
        tx.oncomplete=()=>resolve();tx.onabort=()=>reject(tx.error);tx.onerror=()=>reject(tx.error);
      });
    }finally{db.close()}
  });
  await restore('Verified V1').click();
  await expect(history.getByRole('status')).toContainText('Local history is full');
  await expect(source).toHaveValue(unsaved);
  expect(writes).toEqual([]);
  expect(errors).toEqual([]);
});
