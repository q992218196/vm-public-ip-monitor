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
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{margin:0;padding:24px;background:#f4f6fa;font:14px system-ui;--el-text-color-primary:#303133;--el-border-color:#ddd;--el-fill-color-light:#f5f7fa;--el-fill-color-lighter:#fafafa;--el-color-primary:#409eff}#app{max-width:900px;margin:auto;background:white;padding:20px;box-sizing:border-box}</style></head><body><div id="app"></div><script type="module">import {createApp, reactive, h} from "vue";import ElementPlus from "element-plus";import "element-plus/dist/index.css";import {createPinia} from "pinia";import {createRouter,createMemoryHistory} from "vue-router";import Monitor from "/src/views/backend/monitor/index.vue";const router=createRouter({history:createMemoryHistory(),routes:[{path:"/rules",component:{render:()=>null}}]});await router.push("/rules");import Events from "/src/views/backend/monitor/events.vue";import AiReport from "/src/views/backend/monitor/AiReport.vue";import TrafficEvidence from "/src/views/backend/monitor/TrafficEvidence.vue";import SiteReport from "/src/views/backend/monitor/SiteReport.vue";import EventReviewReport from "/src/views/backend/monitor/EventReviewReport.vue";const state=reactive({content:"",record:{},view:"ai"});createApp({setup:()=>()=>state.view==="rules"?h(Monitor):state.view==="events"?h(Events):["udp","metrics"].includes(state.view)?h(TrafficEvidence,{record:state.record,windowStatistics:state.view==="metrics"}):state.view==="site"?h(SiteReport,{record:state.record}):state.view==="review"?h(EventReviewReport,{report:state.record}):h(AiReport,{content:state.content})}).use(createPinia()).use(router).use(ElementPlus).mount("#app");window.showReport=(text)=>{state.view="ai";state.content=text};window.showEvidence=(view,record)=>{state.view=view;state.record=record};window.ready=true;</script></body></html>',
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
      kind: "udp_packet_rate",
      evidence: {
        value: 6, threshold: 5, window_seconds: 60,
        udp_rule_statistics: {version: 1, packets_out: 200, observed_seconds: 30},
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
  await page.getByText("样本 UDP 出站流数", { exact: true }).waitFor();
  await page.getByText("计入规则的流数／包数", { exact: true }).waitFor();
  assert.ok((await page.locator("body").textContent()).includes("1 / 200（排除目标端口 53）"));
  assert.equal(await page.getByText("完整握手", { exact: true }).count(), 0);
  assert.equal(
    await page.getByText("198.51.100.1", { exact: true }).count(),
    1,
  );
  let udpText = await page.locator("body").textContent();
  assert.ok(udpText.includes("200 个出站包 ÷ 30 秒") && udpText.includes("6.7 包/秒（排除目标端口 53）"));
  await page.evaluate(() => window.showEvidence("udp", {
    title: "UDP 出站包速率提醒", kind: "udp_packet_rate",
    evidence: {value: 10411, threshold: 10000, window_seconds: 60,
      sample_window_start: "2026-10-04T06:19:57Z", sample_window_end: "2026-10-04T06:20:27Z",
      sample: {transport: "UDP", observed_seconds: 30, udp_packets_out: 406944, udp_flows_out: 351}}
  }));
  await page.getByText("规则平均包速率／阈值", {exact: true}).waitFor();
  udpText = await page.locator("body").textContent();
  assert.ok(udpText.includes("10411 / 10000 包/秒") && udpText.includes("13564.8 包/秒（历史原始 UDP 计数）"));
  assert.ok(udpText.includes("旧记录未保存规则出站包总数和实际观察秒数，无法复算"));
  assert.ok(udpText.includes("30 秒；"));
  await page.evaluate(() => window.showEvidence("udp", {
    title: "UDP 出站流数量提醒", kind: "udp_flow_burst",
    evidence: {value: 1056, threshold: 1000, window_seconds: 60,
      sample: {transport: "UDP", observed_seconds: 30, udp_packets_out: 24325, udp_flows_out: 1056}}
  }));
  await page.getByText("规则最大窗口流数／阈值", {exact: true}).waitFor();
  udpText = await page.locator("body").textContent();
  assert.ok(udpText.includes("1056 / 1000 流") && udpText.includes("流数量取评估范围内单个采集窗口的最大值"));
  assert.ok(udpText.includes("表格流数之和不代表全量流数"));
  await page.evaluate(() => window.showEvidence("metrics", {
    id: 1, ip: "203.0.113.10", window_start: "2026-10-04 06:31:27.000000", window_end: "2026-10-04 06:31:57.000000",
    evidence: {udp_stats_version: 1, udp_filter_version: 1, udp_flows_out: 1056, udp_packets_out: 24325, udp_packets_in: 10350,
      udp_bytes_out: 19810811, udp_bytes_in: 3192657, udp_non_dns_flows_out: 1000, udp_non_dns_packets_out: 23400,
      tcp_attempts: 248, udp_endpoints_truncated: true,
      udp_endpoints: [{peer_ip: "1.1.1.1", peer_port: 53, flows: 56, packets_out: 925, packets_in: 700, bytes_out: 60000, bytes_in: 200000}]}
  }));
  await page.getByRole("heading", {name: "UDP 流量统计", exact: true}).waitFor();
  const metricText = await page.locator(".udp-statistics").textContent();
  assert.ok(metricText.includes("810.8 包/秒") && metricText.includes("5.28 Mbps / 0.85 Mbps"));
  assert.ok(metricText.includes("30 秒；") && metricText.includes("1,056（本窗口不同五元组）"));
  assert.ok(metricText.includes("1,000 / 23,400") && metricText.includes("原始 UDP 总量包含 DNS"));
  assert.ok(metricText.includes("1.1.1.1") && metricText.includes("不是瞬时峰值") && metricText.includes("样本数量不代表全部目标数"));
  assert.equal(await page.getByText("规则命中／阈值", {exact: true}).count(), 0);
  await page.evaluate(() => window.showEvidence("metrics", {
    id: 2, ip: "203.0.113.10", window_start: "2026-10-04 06:31:27", window_end: "2026-10-04 06:31:27",
    evidence: {udp_stats_version: 1, udp_flows_out: 10, udp_packets_out: 100, udp_packets_in: 0, udp_bytes_out: 10000, udp_bytes_in: 0}
  }));
  await page.getByRole("heading", {name: "UDP 流量统计", exact: true}).waitFor();
  assert.ok((await page.locator(".udp-statistics").textContent()).includes("不可计算"));
  await page.evaluate(() => window.showEvidence("udp", {
    title: "远程桌面 RDP 高频连接", kind: "rdp_connections", ip: "203.0.113.10",
    evidence: {value: 317, threshold: 60, sample: {tcp_attempts: 317, completed_handshakes: 317, rst_replies: 3},
      connection_analysis: {conclusion: "连接数量或带宽阈值只能证明活跃程度", completion_ratio: 1}}
  }));
  await page.getByText("登录失败次数", {exact: true}).waitFor();
  assert.equal(await page.getByText("不可观测", {exact: true}).count(), 1);
  assert.equal(await page.getByText("样本 TCP 建连尝试", {exact: true}).count(), 0);
  assert.equal(await page.getByText("完整握手", {exact: true}).count(), 0);
  assert.equal(await page.getByText("配对 RST", {exact: true}).count(), 0);
  assert.ok(!(await page.locator("body").textContent()).includes("317"));
  await page.evaluate(() => window.showEvidence("review", {
    event: {id: 1, ip: "203.0.113.10", kinds: ["rdp_connections"]}, timeline: [], totals: {},
    reasons: [], normal_explanations: [], targets: [], port_targets: [], request_hints: [], evidence_gaps: [], next_steps: []
  }));
  await page.getByRole("heading", {name: "IP 审核报告", exact: true}).waitFor();
  assert.equal(await page.getByText("登录失败次数", {exact: true}).count(), 1);
  assert.equal(await page.getByText("TCP 发起", {exact: true}).count(), 0);
  assert.equal(await page.getByText("主要目标连接样本", {exact: true}).count(), 0);
  await page.evaluate(() => window.showEvidence("review", {
    event: {id: 2, ip: "203.0.113.10", kinds: ["rdp_connections", "smb_connections"]}, timeline: [], totals: {},
    reasons: [], normal_explanations: [], targets: [], port_targets: [], request_hints: [], evidence_gaps: [], next_steps: []
  }));
  await page.getByText("主要目标连接样本", {exact: true}).waitFor();
  assert.equal(await page.getByText("TCP 发起", {exact: true}).count(), 1);
  await page.evaluate(() => window.showEvidence("udp", {
    title: "TCP 连接数量提醒", kind: "tcp_connection_burst",
    evidence: {value: 3226, threshold: 2000, window_seconds: 60, rule_observed_span_seconds: 61, rule_window_count: 2,
      rule_observed_start: "2026-10-03T00:00:00Z", rule_observed_end: "2026-10-03T00:01:01Z",
      sample_window_start: "2026-10-03T00:00:31Z", sample_window_end: "2026-10-03T00:01:01Z",
      sample: {tcp_attempts: 2226, synack_replies: 1650, unique_targets: 256, cardinality_capped: true},
      connection_analysis: {completion_ratio: 0.216}}
  }));
  await page.getByText("样本 TCP 建连尝试", {exact: true}).waitFor();
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
  const nodeFixtures = [{id: "00000000-0000-4000-8000-000000000001", name: "HK 1"}, {id: "00000000-0000-4000-8000-000000000002", name: "TW 2"}];
  const qualityRule = {id: 4, name: "采集覆盖下降", kind: "capture_degraded", threshold: 1, window_seconds: 60, cooldown_seconds: 600, severity: "medium", enabled: true, node_id: null, node_ids: null};
  let savedQualityRule = null;
  await page.route("**/admin/**", async route => {
    const url = new URL(route.request().url());
    const action = url.pathname.split("/").at(-1);
    let data = {};
    if (action === "index" && url.pathname.includes("/Monitor/")) data = {list: [
      {id: 1, name: "高规则", kind: "horizontal_scan", threshold: 100, window_seconds: 60, severity: "high", enabled: true},
      {id: 2, name: "中规则", kind: "smb_connections", threshold: 60, window_seconds: 60, severity: "medium", enabled: false},
      {id: 3, name: "低规则", kind: "tcp_connection_burst", threshold: 2000, window_seconds: 60, severity: "low", enabled: "f"}, qualityRule
    ], super: true};
    else if (action === "index") data = {list: [eventFixture], super: true};
    else if (action === "nodes") data = {list: nodeFixtures, super: true};
    else if (action === "count") data = {total: 1};
    else if (action === "detail" && url.pathname.includes("/Monitor/")) data = {record: qualityRule};
    else if (action === "detail" || action === "progress") data = {event: eventFixture, alerts: [], captures: [captureFixture], analyses: [], ai: {enabled: true, endpoint: "https://api.deepseek.com/chat/completions", model: "deepseek-flash"}};
    else if (action === "reviewReport") data = {report: {event: eventFixture, conclusion: "疑似异常，待复核", category: "needs_review", scope: "Current observed windows only", totals: {attempts: 10, paired_windows: 1, paired_attempts: 10, completed: 8}, timeline: [], reasons: [], normal_explanations: [], targets: [], port_targets: [], request_hints: [], evidence_gaps: [], next_steps: []}};
    else if (action === "save") {savedQualityRule = route.request().postDataJSON().data; data = {id: 4};}
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
  await page.getByText("UDP 包数／流数量仅用于流量统计，不作为异常告警。时间按浏览器本地时区显示。", {exact: true}).waitFor();
  const ruleRows = page.locator(".el-table tbody tr");
  assert.ok((await page.locator(".el-table").textContent()).includes("级别"));
  assert.equal(await ruleRows.nth(0).locator(".el-tag--danger").textContent(), "高");
  assert.ok((await ruleRows.nth(0).locator(".el-tag--success").textContent()).includes("启用"));
  assert.equal(await ruleRows.nth(1).locator(".el-tag--warning").textContent(), "中");
  assert.equal(await ruleRows.nth(1).locator(".el-tag--info").textContent(), "停用");
  assert.equal(await ruleRows.nth(2).locator(".el-tag--success").textContent(), "低");
  assert.equal(await ruleRows.nth(2).locator(".el-tag--info").textContent(), "停用");
  assert.ok((await ruleRows.nth(3).textContent()).includes("全部节点"));
  await ruleRows.nth(3).getByRole("button", {name: "编辑", exact: true}).click();
  const qualityDialog = page.getByRole("dialog", {name: "编辑检测规则", exact: true});
  await qualityDialog.getByText("每采集窗口丢弃计数阈值", {exact: true}).waitFor();
  assert.equal(await qualityDialog.getByText("评估窗口秒", {exact: true}).count(), 0);
  await qualityDialog.locator(".el-form-item").filter({hasText: "检测类型"}).locator(".el-select").click();
  await page.getByRole("option", {name: "采集覆盖下降", exact: true}).waitFor();
  assert.equal(await page.getByRole("option", {name: "UDP 出站流数量", exact: true}).count(), 0);
  assert.equal(await page.getByRole("option", {name: "UDP 出站包速率 PPS", exact: true}).count(), 0);
  await page.keyboard.press("Escape");
  await qualityDialog.getByText("指定节点", {exact: true}).click();
  const nodeSelect = qualityDialog.locator(".el-form-item").filter({hasText: "指定节点（可多选）"}).locator(".el-select");
  await nodeSelect.click();
  await page.getByRole("option", {name: "HK 1", exact: true}).click();
  await page.getByRole("option", {name: "TW 2", exact: true}).click();
  await qualityDialog.getByRole("button", {name: "保存", exact: true}).click();
  await qualityDialog.waitFor({state: "hidden"});
  assert.deepEqual(savedQualityRule.node_ids, nodeFixtures.map(node => node.id));
  assert.equal(savedQualityRule.node_id, null);
  assert.equal(savedQualityRule.kind, "capture_degraded");
  await page.evaluate(() => window.showEvidence("events", {}));
  await page.getByText("仅显示疑似异常、强异常及节点运行异常；一般流量活动在流量窗口查看。同节点、IP 的持续行为合并为事件。", {exact: true}).waitFor();
  await page.locator(".filters .el-select").last().click();
  await page.getByRole("option", {name: "疑似异常，待复核", exact: true}).waitFor();
  assert.equal(await page.getByRole("option", {name: "一般行为提醒", exact: true}).count(), 0);
  await page.keyboard.press("Escape");
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
  await page.getByRole("heading", {name: "IP 审核报告", exact: true}).waitFor();
  const detailHeadings = await page.locator(".el-drawer h3").allTextContents();
  assert.ok(detailHeadings.indexOf("规则证据（主要告警优先）") < detailHeadings.indexOf("PCAP 抓包留存"));
  assert.ok(detailHeadings.indexOf("PCAP 抓包留存") < detailHeadings.indexOf("手动 AI 分析"));
  assert.equal(detailHeadings.at(-1), "IP 审核报告");
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
