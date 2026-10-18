import {expect,type Locator} from '@playwright/test';

/** Current product auto-applies verified matches during draft preparation.
 * An acceptance test must recognize both already-applied mappings and
 * outstanding recommended mappings; it must never reapply duplicates.
 */
export async function verifyOfficialMappings(
  map:Locator,
  targets:readonly string[],
  family:string,
):Promise<void>{
  const suggestion=map.getByLabel('Recommended field matches');
  await expect(suggestion).toBeVisible();
  const current=()=>map.locator('input[aria-label^="Stellar field "]')
    .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
  const before=await current();
  const suggested=await suggestion.innerText();
  for(const target of targets){
    expect(
      before.includes(target)||suggested.includes(target),
      family+' must either have a verified '+target+' mapping or expose a manual suggestion',
    ).toBe(true);
  }
  const bulk=map.getByRole('button',{name:/Apply \d+ recommended match/});
  if(await bulk.isEnabled())await bulk.click();
  const final=await current();
  for(const target of targets){
    expect(final, family+' should map supported field '+target).toContain(target);
  }
  await expect(map.getByLabel('Field mapping checks')).toContainText(
    'All current field mappings passed the sample checks',
  );
  await expect(map.getByLabel('Field changes only')).toBeVisible();
  await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();
}
