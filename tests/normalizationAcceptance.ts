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


/** Inspect the actual accepted destination, not only a recommendation label. */
export async function requireSourceMapping(
  map:Locator,
  source:string,
  target:string,
):Promise<void>{
  const names=await map.locator('input[aria-label^="Source field "]')
    .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
  const index=names.indexOf(source);
  expect(index, 'source field '+source+' must be retained for review').toBeGreaterThanOrEqual(0);
  await expect(map.getByLabel('Stellar field '+index)).toHaveValue(target);
}

/** Negative boundary: a risky suggestion must never be silently accepted. */
export async function requireUnappliedSourceMapping(
  map:Locator,
  source:string,
  unsafeTarget:string,
):Promise<void>{
  const names=await map.locator('input[aria-label^="Source field "]')
    .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
  const index=names.indexOf(source);
  expect(index, 'source field '+source+' must be retained for manual review').toBeGreaterThanOrEqual(0);
  await expect(map.getByLabel('Stellar field '+index)).not.toHaveValue(unsafeTarget);
}
