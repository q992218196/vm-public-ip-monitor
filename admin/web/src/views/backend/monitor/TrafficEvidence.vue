<template>
    <section>
        <h3>{{ isRdp ? 'RDP 登录结果' : record.title || '连接证据' }}</h3>
        <el-alert v-if="!isRdp && analysis.conclusion" type="info" :closable="false" :title="analysis.conclusion" />
        <template v-if="isRdp">
            <el-descriptions :column="1" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item label="登录失败次数"><el-tag type="info">不可观测</el-tag></el-descriptions-item>
            </el-descriptions>
            <p>
                当前仅在宿主机旁路采集，无法可靠读取加密 RDP/TLS/NLA 的登录结果；不可观测不等于失败 0
                次。此规则按常见端口提供服务线索，不能确认实际服务类型。 准确的失败次数需要目标 Windows 的认证日志，连接、握手和 RST
                均不能替代登录结果。
            </p>
        </template>
        <template v-else-if="record.kind === 'capture_degraded'">
            <el-descriptions :column="2" border>
                <el-descriptions-item label="丢弃计数／阈值"
                    >{{ evidence.value ?? '旧记录未保存' }} / {{ evidence.threshold ?? '旧记录未保存' }}</el-descriptions-item
                >
                <el-descriptions-item label="内核丢包">{{ evidence.kernel_drops ?? '未采集' }}</el-descriptions-item>
                <el-descriptions-item label="状态丢弃">{{ evidence.state_dropped ?? '未采集' }}</el-descriptions-item>
                <el-descriptions-item label="上报缓存丢弃">{{ evidence.spool_dropped ?? '未采集' }}</el-descriptions-item>
            </el-descriptions>
            <p>这是单个采集窗口的节点质量提醒，不代表 VM 违规。在“检测规则 → 采集覆盖下降”选择启用节点、阈值和级别；不提供白名单入口。</p>
        </template>
        <template v-else-if="sample.transport === 'UDP'">
            <el-descriptions :column="2" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item :label="isUdpRate ? '规则平均包速率／阈值' : '规则最大窗口流数／阈值'"
                    >{{ evidence.value ?? '未保存' }} / {{ evidence.threshold ?? '未保存' }} {{ isUdpRate ? '包/秒' : '流' }}</el-descriptions-item
                >
                <el-descriptions-item label="规则配置窗口">{{ evidence.window_seconds ?? '未保存' }} 秒</el-descriptions-item>
                <el-descriptions-item label="实际规则覆盖范围">{{ ruleCoverage }}</el-descriptions-item>
                <el-descriptions-item label="样本采集窗口">{{ sampleDuration }}</el-descriptions-item>
                <el-descriptions-item label="样本 UDP 出站流数">{{ sample.udp_flows_out ?? '未采集' }}（不同五元组）</el-descriptions-item>
                <el-descriptions-item v-if="sample.udp_filter_version === 1" label="计入规则的流数／包数"
                    >{{ sample.udp_non_dns_flows_out }} / {{ sample.udp_non_dns_packets_out }}（排除目标端口 53）</el-descriptions-item
                >
                <el-descriptions-item label="样本平均包速率">{{ udpSampleRate }}</el-descriptions-item>
                <el-descriptions-item label="UDP 包数 出／入">{{ sample.udp_packets_out }} / {{ sample.udp_packets_in }}</el-descriptions-item>
                <el-descriptions-item label="UDP 字节 出／入">{{ sample.udp_bytes_out }} / {{ sample.udp_bytes_in }} B</el-descriptions-item>
            </el-descriptions>
            <p v-if="isUdpRate">
                {{ udpCalculation }} 平均速率不表示每一秒的包数，也不是瞬时峰值；下面单独展示平均包速率最高的采集窗口，可能高于规则命中值。
            </p>
            <p v-else>
                流数量取评估范围内单个采集窗口的最大值，不跨窗口累加，不是每秒数量。五元组包含源／目的 IP、源／目的端口和协议；
                改变源端口也会形成另一条流。它不等于目标 IP 数、握手数、应用请求或登录次数。
            </p>
            <p>{{ evidence.note }}</p>
            <el-table :data="sample.udp_endpoints || []" border size="small">
                <el-table-column prop="peer_ip" label="目标 IP" min-width="150" />
                <el-table-column prop="peer_port" label="目标端口" width="100" />
                <el-table-column prop="flows" label="出站流数" width="100" />
                <el-table-column label="包数 出／入" min-width="130"
                    ><template #default="scope">{{ scope.row.packets_out }} / {{ scope.row.packets_in }}</template></el-table-column
                >
                <el-table-column label="字节 出／入" min-width="160"
                    ><template #default="scope">{{ scope.row.bytes_out }} / {{ scope.row.bytes_in }} B</template></el-table-column
                >
            </el-table>
            <p>
                每窗口最多 8 个目标端点样本，表格流数之和不代表全量流数，样本中的目标数也不是全部目标数。UDP
                无握手；服务回复也可能计入出站流，双向流量不代表应用成功。{{
                    sample.udp_flows_capped || sample.udp_endpoints_truncated ? '状态限额或目标样本截断，证据不完整。' : ''
                }}
            </p>
        </template>
        <template v-else>
            <el-descriptions :column="2" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item label="规则命中／阈值"
                    >{{ evidence.value ?? '未保存' }} / {{ evidence.threshold ?? '未保存' }}</el-descriptions-item
                >
                <el-descriptions-item label="规则配置窗口">{{ evidence.window_seconds ?? '未保存' }} 秒</el-descriptions-item>
                <el-descriptions-item label="实际规则覆盖范围">{{ ruleCoverage }}</el-descriptions-item>
                <el-descriptions-item label="样本采集窗口">{{ sampleDuration }}</el-descriptions-item>
                <el-descriptions-item label="样本目标数"
                    >{{ sample.unique_targets ?? '—' }}{{ sample.cardinality_capped ? '（计数可能截断）' : '' }}</el-descriptions-item
                >
                <el-descriptions-item label="样本 TCP 建连尝试">{{ sample.tcp_attempts ?? '—' }}</el-descriptions-item>
                <el-descriptions-item label="SYN-ACK 回复">{{ sample.synack_replies ?? '未采集' }}</el-descriptions-item>
                <el-descriptions-item label="握手回复比例">{{ replyRatio }}</el-descriptions-item>
                <el-descriptions-item label="完整握手">{{ sample.completed_handshakes ?? '未采集' }} · {{ completionRatio }}</el-descriptions-item>
                <el-descriptions-item label="配对 RST">{{ sample.rst_replies ?? '未采集' }}</el-descriptions-item>
                <el-descriptions-item label="等待至少 3 秒仍无回复">{{ sample.mature_no_reply ?? '未采集' }}（不等于失败）</el-descriptions-item>
                <el-descriptions-item label="目标端口">{{ (sample.ports || []).join('、') || '—' }}</el-descriptions-item>
            </el-descriptions>
            <p v-if="record.kind === 'tcp_connection_burst'">
                规则命中值累加评估范围内的 TCP
                发起数；下面的握手、目标和端口来自单个样本窗口。按完整采集窗口统计，边界可能超过配置秒数，范围内也可能有采集间断。TCP 发起不是 HTTP
                请求、登录次数或已成功连接数。
            </p>
            <p>{{ evidence.note }}</p>
            <h4 v-if="endpoints.length">目标连接样本</h4>
            <el-table v-if="endpoints.length" :data="endpoints" border size="small">
                <el-table-column label="目标" min-width="170"
                    ><template #default="scope">{{ scope.row.peer_ip }}:{{ scope.row.peer_port }}</template></el-table-column
                >
                <el-table-column prop="attempts" label="发起" width="65" />
                <el-table-column prop="synack_replies" label="回复" width="65" />
                <el-table-column label="握手 / RST" width="115"
                    ><template #default="scope"
                        >{{ scope.row.completed_handshakes ?? '—' }} / {{ scope.row.rst_replies ?? '—' }}</template
                    ></el-table-column
                >
                <el-table-column label="观察跨度" width="100"
                    ><template #default="scope">{{
                        scope.row.max_observed_span_ms === undefined ? '未采集' : (scope.row.max_observed_span_ms / 1000).toFixed(1) + '秒'
                    }}</template></el-table-column
                >
                <el-table-column label="载荷 出／入" min-width="150"
                    ><template #default="scope">{{ scope.row.payload_out }} / {{ scope.row.payload_in }} B</template></el-table-column
                >
            </el-table>
            <article v-for="(item, index) in endpoints.filter((item) => item.host || item.http_path)" :key="index" class="request-hint">
                <p>{{ item.peer_ip }}:{{ item.peer_port }} · {{ item.scheme }} · {{ item.host || '未观察到域名' }}</p>
                <p v-if="item.http_path">{{ item.http_method }} {{ item.http_path }} · 参数名称：{{ (item.query_keys || []).join('、') || '无' }}</p>
                <p v-else>加密流量或未观察到 HTTP 请求头，无法获取路径和正文。</p>
            </article>
            <p v-if="!endpoints.length">该记录无目标级详细样本；升级 Agent 后的新采集窗口才会包含此证据。</p>
            <p class="evidence-limit">
                每窗口最多 8 个目标样本，按连接发起次数排序；域名／路径是有限的首个请求样本。载荷字节来自观察到的 VM 发起连接前 60
                秒内报文，可能包含重传，不是应用请求成功统计。查询值、Cookie 和正文不保存。
            </p>
        </template>
    </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ record: Record<string, any> }>()
const evidence = computed(() => props.record.evidence || {})
const sample = computed(() => evidence.value.sample || evidence.value)
const analysis = computed(() => evidence.value.connection_analysis || {})
const endpoints = computed<any[]>(() => sample.value.outbound_endpoints || [])
const isRdp = computed(() => props.record.kind === 'rdp_connections')
const isUdpRate = computed(() => props.record.kind === 'udp_packet_rate')
const sampleSeconds = computed(() => {
    const start = Date.parse(evidence.value.sample_window_start || '')
    const end = Date.parse(evidence.value.sample_window_end || '')
    if (Number.isFinite(start) && Number.isFinite(end) && end > start) return (end - start) / 1000
    const seconds = sample.value.observed_seconds
    return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? seconds : null
})
const udpSampleRate = computed(() => {
    const filtered = sample.value.udp_filter_version === 1
    const packets = filtered ? sample.value.udp_non_dns_packets_out : sample.value.udp_packets_out
    if (sampleSeconds.value === null || typeof packets !== 'number' || !Number.isFinite(packets) || packets < 0) return '不可计算'
    return `${(packets / sampleSeconds.value).toFixed(1)} 包/秒（${filtered ? '排除目标端口 53' : '历史原始 UDP 计数'}）`
})
const udpCalculation = computed(() => {
    const stats = evidence.value.udp_rule_statistics
    if (
        stats?.version !== 1 ||
        typeof stats.packets_out !== 'number' ||
        !Number.isFinite(stats.packets_out) ||
        stats.packets_out < 0 ||
        typeof stats.observed_seconds !== 'number' ||
        !Number.isFinite(stats.observed_seconds) ||
        stats.observed_seconds <= 0
    )
        return '旧记录未保存规则出站包总数和实际观察秒数，无法复算；不使用配置秒数推算。'
    return `规则计入 ${stats.packets_out} 个出站包 ÷ ${stats.observed_seconds} 秒实际观察时间 = ${(stats.packets_out / stats.observed_seconds).toFixed(1)} 包/秒，命中值向下取整（排除目标端口 53）。`
})
const ruleCoverage = computed(() => {
    const e = evidence.value
    if (typeof e.rule_observed_span_seconds !== 'number') return '旧记录未保存实际范围'
    return `${e.rule_observed_span_seconds} 秒跨度 / ${e.rule_window_count} 个采集窗口；${timeText(e.rule_observed_start)} 至 ${timeText(e.rule_observed_end)}`
})
const sampleDuration = computed(() => {
    const e = evidence.value
    const start = Date.parse(e.sample_window_start || '')
    const end = Date.parse(e.sample_window_end || '')
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return sampleSeconds.value === null ? '未保存' : `${sampleSeconds.value} 秒`
    return `${((end - start) / 1000).toFixed(3).replace(/\.?0+$/, '')} 秒；${timeText(e.sample_window_start)} 至 ${timeText(e.sample_window_end)}`
})
function timeText(value: string) {
    const date = new Date(value)
    return Number.isFinite(date.getTime()) ? date.toLocaleString() : '未知'
}
const replyRatio = computed(() => {
    let ratio = analysis.value.reply_ratio
    const attempts = sample.value.tcp_attempts
    const replies = sample.value.synack_replies
    if (
        ratio === undefined &&
        typeof analysis.value.completion_ratio === 'number' &&
        Number.isInteger(attempts) &&
        attempts > 0 &&
        Number.isInteger(replies) &&
        replies >= 0 &&
        replies <= attempts
    )
        ratio = replies / attempts
    return typeof ratio === 'number' ? (ratio * 100).toFixed(1) + '%' : '不可计算'
})
const completionRatio = computed(() =>
    typeof analysis.value.completion_ratio === 'number' ? (100 * analysis.value.completion_ratio).toFixed(1) + '%' : '不可计算'
)
</script>
<style scoped>
section p {
    line-height: 1.7;
    overflow-wrap: anywhere;
}
.request-hint {
    padding: 8px 14px;
    margin-top: 12px;
    background: var(--el-fill-color-light);
    border-radius: 8px;
}
.evidence-limit {
    font-size: 12px;
    color: var(--el-text-color-secondary);
}
</style>
