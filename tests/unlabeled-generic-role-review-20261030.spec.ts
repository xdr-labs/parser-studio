import {test,expect} from '@playwright/test';

// Examples are from publicly documented source formats, not device captures.
const watchguard='2024-03-29 15:00:50 Member2 Allow 192.168.228.202 10.0.1.1 webcache/tcp 42973 8080 3-Trusted 1-WCI Allowed 60 63 (Outgoing-proxy-00) proc_id="firewall" rc="100" src_ip_nat="69.164.168.163" tcp_info="offset 10 S 2982213793 win 2105" msg_id="3000-0148"';
const fortinet='date=2018-12-27 time=11:15:40 logid="0100032002" type="event" subtype="system" level="alert" srcip=172.16.200.254 dstip=172.16.200.1 action="login" status="failed"';

test('fully tokenized but unlabeled security log explains unverified field roles',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(watchguard);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('1 of 1 log event parsed completely');
 await expect(summary).toContainText('some values have only positional names');
 await expect(summary).toContainText('Source and destination IP, action, and other field roles are not verified');
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(watchguard);
 await page.getByRole('button',{name:'Review Fields',exact:true}).click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
 await expect(page.getByLabel('Unlabeled field roles need review')).toContainText('source and destination IP roles');
});

test('explicit KV field names do not show the positional warning',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(fortinet);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('1 of 1 log event parsed completely');
 await expect(summary).not.toContainText('only positional names');
});