import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const credentials=JSON.parse(await fs.readFile('../.tools/ui-credentials.json','utf8'));
const browser=await chromium.launch({headless:true,executablePath:process.env.TEST_BROWSER_PATH});
const errors=[];
try {
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8090/admin/login');
 await page.locator('input[type=email]').fill(credentials.email);await page.locator('input[type=password]').fill(credentials.password);
 await page.locator('button[type=submit]').click();await page.waitForURL('**/admin');
 for(const url of ['/admin/nodes','/admin/websites','/admin/alerts']) {
  const r=await page.goto('http://127.0.0.1:8090'+url);assert.equal(r.status(),200);await page.waitForTimeout(250);
 }
 await page.screenshot({path:'../.tools/panel-preview.png',fullPage:true});
 assert.deepEqual(errors,[]);console.log(JSON.stringify({panel_smoke:'passed',pages:4,js_errors:errors.length}));
}finally{await browser.close();}
