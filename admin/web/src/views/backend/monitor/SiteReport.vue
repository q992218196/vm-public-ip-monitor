<template>
    <section class="site-report">
        <el-alert
            v-if="isServiceClue"
            type="info"
            :closable="false"
            :title="
                record.discovery_kind === 'rdp'
                    ? '已观察到 RDP 连接协商；此记录为远程桌面服务线索，不自动探测网页。'
                    : '仅有 TLS 线索，尚无 HTTP 网页证据；不自动探测，需要时可手动验证。'
            "
        />
        <el-alert
            v-if="hasObservedHttpResponse && !hasHttpResponse && record.status !== 'verified'"
            type="info"
            :closable="false"
            title="已配对观察到服务端明文 HTTP 响应，尚未完成主动网页验证；这不代表网站内容或用途已确认，普通 HTTPS 正文无法旁路解密。"
        />
        <el-alert
            v-if="isHttpRequestOnly"
            type="info"
            :closable="false"
            title="仅见客户端 HTTP 请求，未确认服务端返回 HTTP 响应；也可能是对 SSH 等服务的探测，不证明此端口提供 HTTP。"
        />
        <header>
            <h3>站点监控分析</h3>
            <el-tag :type="report.review_required ? 'warning' : 'info'">{{ report.review_required ? '中风险 · 待人工复核' : '风险未确定' }}</el-tag>
        </header>
        <el-alert
            v-if="record.status !== 'verified'"
            type="warning"
            :closable="false"
            :title="
                isHttpRequestOnly
                    ? record.last_probed_at
                        ? '最近一次验证尚未确认有效 HTTP 响应，不能据此确认网站。'
                        : '仅请求线索不进入自动验证；需要时可手动验证。'
                    : hasObservedHttpResponse && !record.last_probed_at
                      ? '已观察响应，尚未完成主动网页验证。'
                      : '最近一次未验证成功；已有分析及截图可能来自历史验证。'
            "
        />
        <el-alert
            v-if="!['manual', 'dns_match', 'ip_only'].includes(record.ownership_status)"
            type="warning"
            :closable="false"
            title="此条仅为客户端请求的域名线索，尚未确认站点归属；历史分类不能作为本 VM 部署该网站的证据。"
        />
        <el-alert
            v-if="record.ownership_evidence?.registration?.type === 'cdn_origin'"
            type="info"
            :closable="false"
            title="此域名已人工登记为 CDN 源站；登记依据与原 DNS 结果保留。验证可能受源站访问限制或证书影响，人工登记不等于确认违规或部署。"
        />
        <el-alert
            v-if="record.ownership_evidence?.origin_test"
            type="info"
            :closable="false"
            title="曾用当前域名的 Host/SNI 直接请求指定 IP 并取得响应，测试时间见下方。默认站点或反向代理也可能响应，需结合截图、页面和客户配置确认归属。"
        />
        <el-descriptions :column="1" border>
            <el-descriptions-item v-if="record.ownership_evidence?.origin_test" label="指定 IP 测试"
                >{{ record.ownership_evidence.origin_test.target_ip }} · {{ record.ownership_evidence.origin_test.checked_at }} ·
                {{ record.ownership_evidence.origin_test.limitations }}</el-descriptions-item
            >
            <el-descriptions-item v-if="record.ownership_evidence?.registration" label="源站登记依据">{{
                record.ownership_evidence.registration.reason
            }}</el-descriptions-item>
            <el-descriptions-item v-if="record.ownership_evidence?.previous_dns" label="登记前 DNS 证据"
                >{{ record.ownership_evidence.previous_dns.evidence?.addresses?.join(', ') || '未取得解析地址' }} ·
                {{ record.ownership_evidence.previous_dns.evidence?.checked_at || '—' }}</el-descriptions-item
            >
            <el-descriptions-item label="归属核实">{{ ownershipLabel }}；DNS 匹配也不等于已确认站点部署。</el-descriptions-item>
            <el-descriptions-item v-if="record.ownership_evidence" label="归属证据"
                >{{ record.ownership_evidence.addresses?.join(', ') || '人工登记／IP 对比' }} · {{ record.ownership_evidence.checked_at }} ·
                {{ record.last_error || '' }}</el-descriptions-item
            >
            <el-descriptions-item label="公网 IP">{{ record.ip || '—' }}</el-descriptions-item>
            <el-descriptions-item label="域名／端口"
                >{{ record.host || (isHttpRequestOnly ? '未提供域名' : 'IP 直连') }} : {{ record.port }} /
                {{ isHttpRequestOnly ? 'HTTP 请求（非服务证明）' : isServiceClue ? 'TLS 服务线索' : record.scheme }}</el-descriptions-item
            >
            <el-descriptions-item label="证据阶段">{{ discoveryLabel }}</el-descriptions-item>
            <el-descriptions-item label="识别来源">{{
                record.source === 'tls_alpn'
                    ? '客户端声明支持 HTTP；尚需验证响应'
                    : record.source === 'rdp_negotiation'
                      ? 'RDP 协商请求（不代表认证成功）'
                      : record.source === 'tls_sni'
                        ? 'TLS 握手；SNI 本身不能证明网站'
                        : record.source === 'http_host'
                          ? '客户端 HTTP 请求头（不代表服务端响应）'
                          : record.source === 'http_response'
                            ? '配对观察的服务端明文 HTTP 响应'
                            : record.source === 'manual'
                              ? '人工登记'
                              : record.source === 'active_candidate'
                                ? '人工指定探测'
                                : record.source
            }}</el-descriptions-item>
            <el-descriptions-item label="站点标题">{{ record.title || '—' }}</el-descriptions-item>
            <el-descriptions-item label="网站描述">{{ record.description || '未提供' }}</el-descriptions-item>
            <el-descriptions-item label="业务类型">{{ report.business_type || record.category || '未分类' }}</el-descriptions-item>
            <el-descriptions-item label="性质">{{ report.nature || '待人工核实' }}</el-descriptions-item>
            <el-descriptions-item label="人工分类">{{ record.manual_category || '未填写' }}</el-descriptions-item>
            <el-descriptions-item label="被动观察 HTTP 响应">{{
                hasObservedHttpResponse ? record.observed_http_status : '未观察／未保存'
            }}</el-descriptions-item>
            <el-descriptions-item label="主动验证 HTTP 状态">{{ hasHttpResponse ? record.http_status : '尚未取得有效响应' }}</el-descriptions-item>
            <el-descriptions-item label="观察时间">{{ observedAt }}</el-descriptions-item>
        </el-descriptions>
        <h4>分析说明</h4>
        <p>{{ report.summary || '该记录尚无新版分析报告，请重新验证／截图。未命中规则不代表已经确认合规。' }}</p>
        <article v-for="(finding, index) in report.findings || []" :key="index">
            <h4>{{ finding.category }}</h4>
            <p>{{ finding.explanation }}</p>
            <blockquote v-for="(item, evidenceIndex) in finding.evidence" :key="evidenceIndex">
                <small>{{ sourceLabel(item.source) }} · 命中“{{ item.keyword }}”</small>
                <p>{{ item.excerpt }}</p>
            </blockquote>
        </article>
        <h4>观察范围与限制</h4>
        <ul>
            <li v-for="(item, index) in report.limitations || ['基于公开首页文本规则，需人工复核']" :key="index">{{ item }}</li>
        </ul>
        <p class="fingerprint">内容 SHA-256：{{ record.content_hash || '—' }}</p>
        <el-button @click="exportReport">导出分析报告 JSON</el-button>
    </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ record: Record<string, any> }>()
const report = computed(() => props.record.classification || {})
const hasHttpResponse = computed(() => {
    const status = Number(props.record.http_status)
    return Number.isInteger(status) && status >= 100 && status <= 599
})
const hasObservedHttpResponse = computed(() => {
    const status = Number(props.record.observed_http_status)
    return Number.isInteger(status) && status >= 100 && status <= 599
})
const hasManualEvidence = computed(
    () => props.record.source === 'manual' || props.record.ownership_status === 'manual' || Boolean(props.record.manual_category)
)
const hasWebEvidence = computed(
    () =>
        hasHttpResponse.value ||
        hasObservedHttpResponse.value ||
        props.record.status === 'verified' ||
        hasManualEvidence.value ||
        Boolean(props.record.screenshot_path)
)
const isHttpRequestOnly = computed(
    () => (props.record.source === 'http_host' || props.record.discovery_kind === 'http_request') && !hasWebEvidence.value
)
const isServiceClue = computed(() => ['rdp', 'tls_unknown'].includes(props.record.discovery_kind) && !hasWebEvidence.value)
const discoveryLabel = computed(() => {
    if (hasHttpResponse.value) return '已获 HTTP 响应'
    if (props.record.status === 'verified') return '已验证（历史记录）'
    if (hasManualEvidence.value) return '人工登记／确认'
    if (props.record.screenshot_path) return '历史网页证据（待复验）'
    if (hasObservedHttpResponse.value) return 'HTTP 响应线索（待验证）'
    if (isHttpRequestOnly.value) return '仅 HTTP 请求（不自动验证）'
    return isServiceClue.value ? '仅服务线索' : '网页候选（待验证）'
})
const ownershipLabel = computed(() =>
    props.record.ownership_status === 'ip_only' && isHttpRequestOnly.value
        ? '未提供域名（仅请求）'
        : (
              {
                  manual: '人工登记',
                  dns_match: '解析匹配',
                  ip_only: 'IP 直连',
                  dns_mismatch: '解析不匹配',
                  dns_unknown: 'DNS 暂不可确认',
                  unverified: '归属待验证',
                  origin_response: '指定 IP 响应，归属待核实',
              } as Record<string, string>
          )[props.record.ownership_status] || '归属待验证'
)
const observedAt = computed(() => {
    const value = report.value.observed_at
    if (!value) return '旧记录未标明报告生成时间'
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
})
function sourceLabel(source: string) {
    return ({ title: '标题', description: '网站描述', body: '首页正文' } as Record<string, string>)[source] || source
}
function exportReport() {
    const blob = new Blob([JSON.stringify(props.record, null, 2)], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'site-report-' + props.record.id + '.json'
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<style scoped>
.site-report header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 16px;
}
.site-report h3 {
    margin: 0;
}
.site-report h4 {
    margin: 20px 0 8px;
}
.site-report p {
    line-height: 1.8;
    overflow-wrap: anywhere;
}
.site-report blockquote {
    margin: 10px 0;
    border-left: 3px solid var(--el-color-warning);
    padding: 12px 16px;
    background: var(--el-fill-color-light);
}
.site-report blockquote p {
    margin: 4px 0 0;
}
.site-report small,
.fingerprint {
    color: var(--el-text-color-secondary);
}
.site-report li {
    line-height: 1.8;
}
</style>
