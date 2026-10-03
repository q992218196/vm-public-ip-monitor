import assert from "node:assert/strict";
import { access, mkdir, unlink, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createServer } from "../web/node_modules/vite/dist/node/index.js";
import { chromium } from "../../worker/node_modules/playwright/index.mjs";

const webRoot = fileURLToPath(new URL("../web/", import.meta.url));
const fixture = "ai-report-test-" + randomUUID() + ".html";
const fixturePath = webRoot + "/" + fixture;
let server, browser;
try {
  await writeFile(
    fixturePath,
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{margin:0;padding:24px;background:#f4f6fa;font:14px system-ui;--el-text-color-primary:#303133;--el-border-color:#ddd;--el-fill-color-light:#f5f7fa;--el-fill-color-lighter:#fafafa;--el-color-primary:#409eff}#app{max-width:900px;margin:auto;background:white;padding:20px;box-sizing:border-box}</style></head><body><div id="app"></div><script type="module">import {createApp, reactive, h} from "vue";import ElementPlus from "element-plus";import "element-plus/dist/index.css";import {createPinia} from "pinia";import {createRouter,createMemoryHistory} from "vue-router";import Monitor from "/src/views/backend/monitor/index.vue";const router=createRouter({history:createMemoryHistory(),routes:[{path:"/rules",component:{render:()=>null}}]});await router.push("/rules");import Events from "/src/views/backend/monitor/events.vue";import AiReport from "/src/views/backend/monitor/AiReport.vue";import TrafficEvidence from "/src/views/backend/monitor/TrafficEvidence.vue";import SiteReport from "/src/views/backend/monitor/SiteReport.vue";const state=reactive({content:"",record:{},view:"ai"});createApp({setup:()=>()=>state.view==="rules"?h(Monitor):state.view==="events"?h(Events):state.view==="udp"?h(TrafficEvidence,{record:state.record}):state.view==="site"?h(SiteReport,{record:state.record}):h(AiReport,{content:state.content})}).use(createPinia()).use(router).use(ElementPlus).mount("#app");window.showReport=(text)=>{state.view="ai";state.content=text};window.showEvidence=(view,record)=>{state.view=view;state.record=record};window.ready=true;</script></body></html>',
  );
  server = await createServer({
    root: webRoot,
    configFile: webRoot + "/vite.config.ts",
    server: { host: "127.0.0.1", port: 0, open: false },
  });
  await server.listen();
  const port = server.httpServer.address().port;
  const options = { headless: true };
  if (process.env.AI_REPORT_BROWSER)
    options.executablePath = process.env.AI_REPORT_BROWSER;
  else if (process.platform === "win32")
    options.executablePath =
      "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
  browser = await chromium.launch(options);
  const page = await browser.newPage({
    viewport: { width: 1280, height: 1100 },
  });
  const errors = [],
    externalRequests = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.route("**/*", (route) => {
    if (new URL(route.request().url()).hostname !== "127.0.0.1") {
      externalRequests.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  await page.goto("http://127.0.0.1:" + port + "/" + fixture);
  await page.waitForFunction(() => window.ready);
  externalRequests.length = 0; // Observe requests caused by reports, after the browser initialization.
  const report =
    '# 流量证据分析报告\n\n## 一、观察事实\n\n**完成三次握手 1142 条**，本次抓包 60 秒。\n\n- 目标 \x60121.196.227.81:60093\x60\n- 请求线索 POST /node/instance\n\n## 二、置信度评估\n\n| 判断 | 置信度 | 理由 |\n|---|---|---|\n| 当前窗口高频连接 | 高 | 1249 条流，1142 条完成握手 |\n| 真实横向扫描 | 低–中 | 缺少目标日志，未回复不等于失败 |\n\n## 三、结论\n\n> 有候选特征，证据不足以认定违规。\n\n<img src="https://example.invalid/tracker" onerror="window.pwned=1">\n\n![远程图片](https://example.invalid/tracker) [链接](javascript:alert(1))\n\n[正常链接](https://example.invalid/read)\n\n<script>window.pwned=1</script>';
  await page.evaluate((text) => window.showReport(text), report);
  await page.locator(".ai-report h1").waitFor();
  assert.equal(await page.locator(".ai-report h2").count(), 3);
  assert.equal(await page.locator(".ai-report table tbody tr").count(), 2);
  assert.equal(
    await page.locator(".ai-report strong").textContent(),
    "完成三次握手 1142 条",
  );
  assert.equal(await page.locator(".ai-report li").count(), 2);
  assert.equal(
    await page
      .locator(
        ".ai-report img, .ai-report script, .ai-report a, .ai-report [onerror]",
      )
      .count(),
    0,
  );
  assert.equal(await page.evaluate(() => window.pwned), undefined);
  if (process.env.AI_REPORT_SCREENSHOTS) {
    await mkdir(process.env.AI_REPORT_SCREENSHOTS, { recursive: true });
    await page.screenshot({
      path: process.env.AI_REPORT_SCREENSHOTS + "/ai-report-desktop.png",
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 390, height: 900 });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
    false,
  );
  if (process.env.AI_REPORT_SCREENSHOTS)
    await page.screenshot({
      path: process.env.AI_REPORT_SCREENSHOTS + "/ai-report-mobile.png",
      fullPage: true,
    });
  await page.evaluate(
    (text) =>
      window.showReport(
        String.fromCharCode(96, 96, 96) +
          "markdown\n" +
          text +
          "\n" +
          String.fromCharCode(96, 96, 96),
      ),
    report,
  );
  await page.waitForFunction(
    () => document.querySelectorAll(".ai-report h2").length === 3,
  );
  await page.evaluate(() =>
    window.showReport("旧报告：证据不足。\n请核查客户业务。"),
  );
  await page.waitForFunction(() =>
    document.querySelector(".ai-report").textContent.includes("旧报告"),
  );
  assert.equal(await page.locator(".ai-report br").count(), 1);
  await page.setViewportSize({ width: 1280, height: 1100 });
  await page.evaluate(() =>
    window.showEvidence("udp", {
      title: "UDP 出站包速率提醒",
      evidence: {
        sample: {
          transport: "UDP",
          observed_seconds: 30,
          udp_filter_version: 1,
          udp_non_dns_flows_out: 1,
          udp_non_dns_packets_out: 200,
          udp_flows_out: 2,
          udp_packets_out: 600,
          udp_packets_in: 20,
          udp_bytes_out: 24000,
          udp_bytes_in: 800,
          udp_endpoints: [
            {
              peer_ip: "198.51.100.1",
              peer_port: 443,
              flows: 1,
              packets_out: 200,
              packets_in: 20,
              bytes_out: 24000,
              bytes_in: 800,
            },
          ],
        },
      },
    }),
  );
  await page.getByText("UDP 出站流数", { exact: true }).waitFor();
  await page.getByText("计入规则的流数／包数", { exact: true }).waitFor();
  assert.ok((await page.locator("body").textContent()).includes("1 / 200（排除目标端口 53）"));
  assert.equal(await page.getByText("完整握手", { exact: true }).count(), 0);
  assert.equal(
    await page.getByText("198.51.100.1", { exact: true }).count(),
    1,
  );
  await page.evaluate(() => window.showEvidence("udp", {
    title: "TCP 连接数量提醒", kind: "tcp_connection_burst",
    evidence: {value: 3226, threshold: 2000, window_seconds: 60, rule_observed_span_seconds: 61, rule_window_count: 2,
      rule_observed_start: "2026-10-03T00:00:00Z", rule_observed_end: "2026-10-03T00:01:01Z",
      sample_window_start: "2026-10-03T00:00:31Z", sample_window_end: "2026-10-03T00:01:01Z",
      sample: {tcp_attempts: 2226, synack_replies: 1650, unique_targets: 256, cardinality_capped: true},
      connection_analysis: {completion_ratio: 0.216}}
  }));
  await page.getByText("样本 TCP 发起", {exact: true}).waitFor();
  const tcpText = await page.locator(".el-descriptions").textContent();
  assert.ok(tcpText.includes("3226 / 2000") && tcpText.includes("2226"));
  assert.ok(tcpText.includes("61 秒跨度 / 2 个采集窗口") && tcpText.includes("30 秒；"));
  assert.ok(tcpText.includes("74.1%") && tcpText.includes("计数可能截断"));
  await page.evaluate(() =>
    window.showEvidence("site", {
      status: "verified",
      ownership_status: "origin_response",
      ip: "203.0.113.10",
      host: "hidden.example",
      port: 443,
      scheme: "https",
      ownership_evidence: {
        addresses: ["198.51.100.1"],
        origin_test: {
          target_ip: "203.0.113.10",
          checked_at: "2026-10-03T00:00:00Z",
        },
      },
    }),
  );
  await page.getByText("指定 IP 测试", { exact: true }).waitFor();
  assert.ok(
    (await page.locator(".site-report").textContent()).includes(
      "指定 IP 响应，归属待核实",
    ),
  );
  assert.ok(
    (await page.locator(".site-report").textContent()).includes(
      "默认站点或反向代理也可能响应",
    ),
  );
  const eventFixture = {id: 933, title: "SMB 服务高频连接（待复核）", ip: "103.123.132.239", node_name: "TW 2", severity: "medium", status: "open", kinds: ["horizontal_scan", "smb_connections"], quality: {}, first_seen_at: "2026-10-03 07:01:48", last_seen_at: "2026-10-03 07:02:48"};
  const captureFixture = {id: "test-pcap", status: "uploaded", bytes: 4, metadata: {}, created_at: "2026-10-03 07:01:48"};
  let requestedMode = null;
  await page.route("**/admin/**", async route => {
    const url = new URL(route.request().url());
    const action = url.pathname.split("/").at(-1);
    let data = {};
    if (action === "index" && url.pathname.includes("/Monitor/")) data = {list: [
      {id: 1, name: "高规则", kind: "horizontal_scan", threshold: 100, window_seconds: 60, severity: "high", enabled: true},
      {id: 2, name: "中规则", kind: "smb_connections", threshold: 60, window_seconds: 60, severity: "medium", enabled: false},
      {id: 3, name: "低规则", kind: "tcp_connection_burst", threshold: 2000, window_seconds: 60, severity: "low", enabled: "f"}
    ], super: true};
    else if (action === "index") data = {list: [eventFixture], super: true};
    else if (action === "nodes") data = {list: [], super: true};
    else if (action === "count") data = {total: 1};
    else if (action === "detail" || action === "progress") data = {event: eventFixture, alerts: [], captures: [captureFixture], analyses: [], ai: {enabled: true, endpoint: "https://api.deepseek.com/chat/completions", model: "deepseek-flash"}};
    else if (action === "reviewReport") data = {report: null};
    else if (action === "whitelistPreview") data = {target_ports: {"112.121.183.102": [11000,11001,11002], "43.128.8.64": [3389]}, fingerprint: "reviewed-profile"};
    else if (action === "requestAi") requestedMode = route.request().postDataJSON().evidence_mode;
    else if (action === "download") {
      await new Promise(resolve => setTimeout(resolve, 65000));
      return route.fulfill({status: 200, contentType: "application/vnd.tcpdump.pcap", body: "pcap"});
    }
    return route.fulfill({json: {code: 1, msg: "", data}});
  });
  await page.evaluate(() => window.showEvidence("rules", {}));
  await page.getByText("高规则", {exact: true}).waitFor();
  const ruleRows = page.locator(".el-table tbody tr");
  assert.ok((await page.locator(".el-table").textContent()).includes("级别"));
  assert.equal(await ruleRows.nth(0).locator(".el-tag--danger").textContent(), "高");
  assert.ok((await ruleRows.nth(0).locator(".el-tag--success").textContent()).includes("启用"));
  assert.equal(await ruleRows.nth(1).locator(".el-tag--warning").textContent(), "中");
  assert.equal(await ruleRows.nth(1).locator(".el-tag--info").textContent(), "停用");
  assert.equal(await ruleRows.nth(2).locator(".el-tag--success").textContent(), "低");
  assert.equal(await ruleRows.nth(2).locator(".el-tag--info").textContent(), "停用");
  await page.evaluate(() => window.showEvidence("events", {}));
  await page.getByRole("button", {name: "加入白名单", exact: true}).first().waitFor();
  await page.getByRole("button", {name: "加入白名单", exact: true}).first().click();
  await page.getByText("112.121.183.102", {exact: true}).waitFor();
  assert.ok((await page.locator(".el-dialog").textContent()).includes("11000, 11001, 11002"));
  await page.getByRole("button", {name: "取消", exact: true}).click();
  assert.ok((await page.locator(".el-table__header").first().textContent()).includes("主要告警"));
  const headlineBox = await page.getByRole("button", {name: eventFixture.title, exact: true}).boundingBox();
  const countBox = await page.getByRole("button", {name: "共 2 类命中，查看全部", exact: true}).boundingBox();
  assert.ok(countBox.y >= headlineBox.y + headlineBox.height, "Other rule hits must remain visible below the headline");
  await page.getByRole("button", {name: "共 2 类命中，查看全部", exact: true}).click();
  await page.getByRole("heading", {name: "SMB 服务高频连接（待复核） · 103.123.132.239", exact: true}).waitFor();
  await page.getByRole("button", {name: "AI 分析", exact: true}).click();
  await page.getByText("逐包文本前 2 MiB", {exact: true}).click();
  await page.getByRole("button", {name: "提交分析", exact: true}).click();
  await page.getByRole('dialog', {name: '手动申请 AI 分析', exact: true}).waitFor({state: 'hidden'});
  assert.equal(requestedMode, "packet_excerpt");
  const downloaded = page.waitForEvent("download", {timeout: 80000});
  await page.getByRole("button", {name: "下载 PCAP", exact: true}).click();
  await page.getByText("正在下载，持续传输不会在一分钟后取消。", {exact: true}).waitFor();
  const artifact = await downloaded;
  assert.equal(artifact.suggestedFilename(), "test-pcap.pcap");
  assert.equal(await artifact.failure(), null);
  assert.deepEqual(errors, []);
  assert.deepEqual(externalRequests, []);
  console.log(
    "AI Markdown headings, lists, tables, old reports, fenced reports, mobile width, XSS/network isolation, UDP evidence and source test provenance passed.",
  );
} finally {
  if (browser) await browser.close();
  if (server) await server.close();
  try {
    await access(fixturePath);
    await unlink(fixturePath);
  } catch {}
}
