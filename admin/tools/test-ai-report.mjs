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
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{margin:0;padding:24px;background:#f4f6fa;font:14px system-ui;--el-text-color-primary:#303133;--el-border-color:#ddd;--el-fill-color-light:#f5f7fa;--el-fill-color-lighter:#fafafa;--el-color-primary:#409eff}#app{max-width:900px;margin:auto;background:white;padding:20px;box-sizing:border-box}</style></head><body><div id="app"></div><script type="module">import {createApp, reactive, h} from "vue";import AiReport from "/src/views/backend/monitor/AiReport.vue";const state=reactive({content:""});createApp({setup:()=>()=>h(AiReport,{content:state.content})}).mount("#app");window.showReport=(text)=>state.content=text;window.ready=true;</script></body></html>',
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
  assert.deepEqual(errors, []);
  assert.deepEqual(externalRequests, []);
  console.log(
    "AI Markdown headings, lists, tables, old reports, fenced reports, mobile width and XSS/network isolation passed.",
  );
} finally {
  if (browser) await browser.close();
  if (server) await server.close();
  try {
    await access(fixturePath);
    await unlink(fixturePath);
  } catch {}
}
