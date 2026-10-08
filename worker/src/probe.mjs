import {chromium} from 'playwright';
import {createHash} from 'node:crypto';
import {target, permittedURL} from './security.mjs';
import {pinnedProxy} from './proxy.mjs';
import {classify} from './classify.mjs';
import {preflight,needsBrowser} from './preflight.mjs';
import {directoryBytes} from './temp.mjs';
import {verifyOwnership, canRequestWebsite, originTestResult} from './ownership.mjs';

export async function probe(task,limits={}) {
  const manual=task.request_source==='manual'||task.source==='manual'||task.mode==='origin_test';
  if(!manual && (['rdp','tls_unknown'].includes(task.discovery_kind)||(!task.discovery_kind&&(task.source==='rdp_negotiation'||(task.port===3389&&task.source==='tls_sni'))))) {
    return {status:'failed',error:'服务线索不自动探测网页；需要时可手动验证'};
  }
  const diskLimit=limits.diskLimitBytes||512*1024*1024;
  if(limits.dataDir && await directoryBytes(limits.dataDir)>diskLimit)throw new Error('Worker disk budget exhausted');
  const t = target(task);
  const ownership = await verifyOwnership(task);
  if (!canRequestWebsite(task,ownership)) return {status:'failed',...ownership,error:ownership.ownership_status==='dns_mismatch'?'请求 Host/SNI 的 DNS 未指向此公网 IP，保留为未归属线索，未请求网页':'DNS 归属核实暂不可用，未请求网页'};
  let checked;
  try {checked=await preflight(t,manual?8000:3000);}catch(error){error.ownership=ownership;throw error;}
  if(!needsBrowser(checked))return {status:'verified',...originTestResult(task,ownership),http_status:checked.status,final_url:t.url,
    category:'非网页 HTTP 服务',classification:{method:'http_headers',confidence:0,review_required:false,
      summary:`已收到 HTTP ${checked.status} 响应，内容类型 ${checked.contentType}；未启动浏览器，未分析正文或截图。`,reasons:['仅验证 HTTP 响应头；不代表服务用途或合规性']}};
  const release=limits.acquireRender?await limits.acquireRender():()=>{};
  let proxy;
  let browser, watchdog, diskWatch, checkingDisk=false, diskExceeded=false;
  try {
    proxy = await pinnedProxy(t);
    const browserEnv = Object.fromEntries(['PATH','HOME','XDG_CACHE_HOME','USERPROFILE','SYSTEMROOT','WINDIR','TMPDIR','TMP','TEMP','LANG'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
    browser = await chromium.launch({headless: true, timeout:10000, chromiumSandbox: process.platform === 'linux', proxy: {server: proxy.address}, env: browserEnv,
      args: ['--disable-quic', '--proxy-bypass-list=<-loopback>', '--disk-cache-size=16777216', '--media-cache-size=1048576', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']});
    if(limits.dataDir)diskWatch=setInterval(async()=>{
      if(checkingDisk)return;checkingDisk=true;
      try{if(await directoryBytes(limits.dataDir)>diskLimit){diskExceeded=true;await browser.close();}}catch{}finally{checkingDisk=false;}
    },1000);
    watchdog = setTimeout(() => browser.close().catch(() => {}), 45000);
    const context = await browser.newContext({viewport: {width: 1365, height: 900}, acceptDownloads: false, serviceWorkers: 'block', ignoreHTTPSErrors: false});
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
    const description = (await page.locator('meta[name="description" i], meta[property="og:description" i], meta[name="twitter:description" i]')
      .evaluateAll(elements => elements.map(element => element.getAttribute('content') || '').find(value => value.trim()) || '').catch(() => ''))
      .replace(/\s+/g, ' ').trim().slice(0, 1024);
    const text = (await page.locator('body').innerText({timeout: 3000}).catch(() => '')).slice(0, 64000);
    const screenshot = await page.screenshot({type: 'png', fullPage: false, timeout: 10000});
    if(diskExceeded)throw new Error('Worker disk budget exceeded during probe');
    const classified = classify(title, text, {description});
    classified.classification.observed_at = new Date().toISOString();
    classified.classification.reasons.push('仅首页；第三方资源及跨站跳转默认阻止');
    return {status: 'verified', ...originTestResult(task,ownership), title, description, http_status: response.status(), final_url: page.url().slice(0,2048), ...classified,
      content_hash: createHash('sha256').update(title + '\n' + description + '\n' + text).digest('hex'), screenshot: screenshot.length <= 2*1024*1024 ? screenshot.toString('base64') : null};
  } catch(error) {error.ownership=ownership;throw error;} finally {clearTimeout(watchdog);clearInterval(diskWatch);try{if(browser)await browser.close().catch(()=>{});if(proxy)await proxy.close();}finally{release();}}
}
