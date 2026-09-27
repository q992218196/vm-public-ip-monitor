import {chromium} from 'playwright';
import {createHash} from 'node:crypto';
import {target, permittedURL} from './security.mjs';
import {pinnedProxy} from './proxy.mjs';
import {classify} from './classify.mjs';
import {preflight} from './preflight.mjs';
import {directoryBytes} from './temp.mjs';

export async function probe(task,limits={}) {
  const diskLimit=limits.diskLimitBytes||512*1024*1024;
  if(limits.dataDir && await directoryBytes(limits.dataDir)>diskLimit)throw new Error('Worker disk budget exhausted');
  const t = target(task);
  await preflight(t);
  const proxy = await pinnedProxy(t);
  let browser, watchdog, diskWatch, checkingDisk=false, diskExceeded=false;
  try {
    const browserEnv = Object.fromEntries(['PATH','HOME','XDG_CACHE_HOME','USERPROFILE','SYSTEMROOT','WINDIR','TMPDIR','TMP','TEMP','LANG'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
    browser = await chromium.launch({headless: true, chromiumSandbox: process.platform === 'linux', proxy: {server: proxy.address}, env: browserEnv,
      args: ['--disable-quic', '--proxy-bypass-list=<-loopback>', '--disk-cache-size=16777216', '--media-cache-size=1048576', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']});
    if(limits.dataDir)diskWatch=setInterval(async()=>{
      if(checkingDisk)return;checkingDisk=true;
      try{if(await directoryBytes(limits.dataDir)>diskLimit){diskExceeded=true;await browser.close();}}catch{}finally{checkingDisk=false;}
    },1000);
    const context = await browser.newContext({viewport: {width: 1365, height: 900}, acceptDownloads: false, serviceWorkers: 'block', ignoreHTTPSErrors: false});
    watchdog = setTimeout(() => browser.close().catch(() => {}), 45000);
    await context.route('**/*', async route => {
      const req = route.request();
      if (!permittedURL(req.url(), t) || ['media','websocket'].includes(req.resourceType()) || !['GET','HEAD'].includes(req.method())) return route.abort();
      return route.continue();
    });
    await context.routeWebSocket('**/*', ws => ws.close());
    const page = await context.newPage();page.on('dialog', d => d.dismiss());page.on('download', d => d.cancel());
    const response = await page.goto(t.url, {waitUntil: 'domcontentloaded', timeout: 20000});
    if (!response || !permittedURL(page.url(), t)) throw new Error('No valid HTTP response or off-origin redirect');
    await page.waitForTimeout(1000);
    const title = (await page.title()).slice(0, 255);
    const text = (await page.locator('body').innerText({timeout: 3000}).catch(() => '')).slice(0, 64000);
    const screenshot = await page.screenshot({type: 'png', fullPage: false, timeout: 10000});
    if(diskExceeded)throw new Error('Worker disk budget exceeded during probe');
    const classified = classify(title, text);
    classified.classification.reasons.push('仅首页；第三方资源及跨站跳转默认阻止');
    return {status: 'verified', title, http_status: response.status(), final_url: page.url().slice(0,2048), ...classified,
      content_hash: createHash('sha256').update(title + '\n' + text).digest('hex'), screenshot: screenshot.length <= 2*1024*1024 ? screenshot.toString('base64') : null};
  } finally {clearTimeout(watchdog);clearInterval(diskWatch);if(browser)await browser.close().catch(()=>{});await proxy.close();}
}
