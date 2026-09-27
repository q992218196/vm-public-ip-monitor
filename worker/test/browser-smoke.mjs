// Local-only integration fixture: deliberately constructs a loopback proxy target
// without calling the production target() validator, which rejects loopback.
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {pinnedProxy} from '../src/proxy.mjs';
import {classify} from '../src/classify.mjs';
const origin=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end('<!doctype html><html><head><title>VM Monitor Fixture</title></head><body style="font:24px sans-serif;padding:40px"><h1>测试管理后台</h1><p>管理员登录</p></body></html>');});
await new Promise(r=>origin.listen(0,'127.0.0.1',r));const port=origin.address().port;
const t={ip:'127.0.0.1',host:'fixture.example',port,scheme:'http',origin:`http://fixture.example:${port}`,url:`http://fixture.example:${port}/`};
const proxy=await pinnedProxy(t);let browser;
try {
 browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER_PATH?{executablePath:process.env.TEST_BROWSER_PATH}:{}),proxy:{server:proxy.address}});
 const page=await browser.newPage({viewport:{width:1000,height:700}});await page.goto(t.url);assert.equal(await page.title(),'VM Monitor Fixture');
 const classification=classify(await page.title(),await page.locator('body').innerText());assert.equal(classification.category,'管理后台');
 const png=await page.screenshot();assert.ok(png.length>1000);
 const blocked=await page.request.get('http://127.0.0.1:1/').catch(()=>null);assert.ok(!blocked||blocked.status()!==200);
 const out=path.resolve('../.tools/worker-fixture.png');await fs.mkdir(path.dirname(out),{recursive:true});await fs.writeFile(out,png);console.log(JSON.stringify({browser_smoke:'passed',screenshot_bytes:png.length,classification:classification.category}));
}finally{if(browser)await browser.close();await proxy.close();await new Promise(r=>origin.close(r));}
