<template>
    <section>
        <h3 v-if="!compact">{{ isRdp ? 'RDP 登录结果' : isWindow ? '流量窗口统计' : record.title || '连接证据' }}</h3>
        <el-tag v-if="!isWindow && !isRdp && record.assessment_category" :type="record.assessment_category === 'strong_anomaly' ? 'warning' : 'info'">
            {{
                record.assessment_category === 'strong_anomaly'
                    ? '较强异常证据，需复核'
                    : record.assessment_category === 'behavior_notice'
                      ? '历史行为提醒'
                      : '待复核'
            }}
        </el-tag>
        <div v-if="isWindow && sample.udp_stats_version === 1" class="udp-statistics">
            <h4>UDP 流量统计</h4>
            <el-descriptions :column="2" border>
                <el-descriptions-item label="实际采集时长">{{ sampleDuration }}</el-descriptions-item>
                <el-descriptions-item label="UDP 出站流数">{{ countText(sample.udp_flows_out) }}（本窗口不同五元组）</el-descriptions-item>
                <el-descriptions-item label="UDP 平均出站包速率">{{ averageText(sample.udp_packets_out, '包/秒') }}</el-descriptions-item>
                <el-descriptions-item label="UDP 平均带宽 出／入"
                    >{{ averageText(sample.udp_bytes_out, 'Mbps', 8 / 1000000) }} /
                    {{ averageText(sample.udp_bytes_in, 'Mbps', 8 / 1000000) }}</el-descriptions-item
                >
                <el-descriptions-item label="UDP 包数 出／入"
                    >{{ countText(sample.udp_packets_out) }} / {{ countText(sample.udp_packets_in) }}</el-descriptions-item
                >
                <el-descriptions-item label="UDP 字节 出／入"
                    >{{ countText(sample.udp_bytes_out) }} / {{ countText(sample.udp_bytes_in) }} B</el-descriptions-item
                >
                <el-descriptions-item v-if="sample.udp_filter_version === 1" label="排除目标端口 53 的出站流数／包数"
                    >{{ countText(sample.udp_non_dns_flows_out) }} / {{ countText(sample.udp_non_dns_packets_out) }}</el-descriptions-item
                >
            </el-descriptions>

            <el-table :data="sample.udp_endpoints || []" border size="small">
                <el-table-column prop="peer_ip" label="对端 IP（样本）" min-width="150" />
                <el-table-column prop="peer_port" label="对端端口" width="100" />
                <el-table-column prop="flows" label="出站流数" width="100" />
                <el-table-column label="包数 出／入" min-width="130"
                    ><template #default="scope">{{ scope.row.packets_out }} / {{ scope.row.packets_in }}</template></el-table-column
                >
                <el-table-column label="字节 出／入" min-width="160"
                    ><template #default="scope">{{ scope.row.bytes_out }} / {{ scope.row.bytes_in }} B</template></el-table-column
                >
            </el-table>
        </div>
        <template v-if="isServiceTarget">
            <el-descriptions :column="2" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item label="不同目标 IP 数／阈值"
                    >{{ evidence.value ?? '未保存' }} / {{ evidence.threshold ?? '未保存' }} 个</el-descriptions-item
                >
                <el-descriptions-item label="服务目的端口">{{ (sample.ports || []).join('、') || '未采集' }}</el-descriptions-item>
                <el-descriptions-item label="规则配置窗口">{{ evidence.window_seconds ?? '未保存' }} 秒</el-descriptions-item>
                <el-descriptions-item label="实际规则覆盖范围">{{ ruleCoverage }}</el-descriptions-item>
                <el-descriptions-item label="登录失败次数"><el-tag type="info">不可观测</el-tag></el-descriptions-item>
            </el-descriptions>

            <el-tag v-if="sample.service_targets_capped || sample.cardinality_capped" type="warning">目标统计截断，仅为观察下界</el-tag>
            <h4>主动建连目标 IP（最多 128 个）</h4>
            <p class="service-targets">{{ serviceTargets.join('、') || '未保存目标列表' }}</p>

            <details v-if="typeof sample.tcp_attempts === 'number'">
                <summary>辅助统计：服务建连尝试</summary>
                <p>{{ countText(sample.tcp_attempts) }} 次主动 SYN 尝试；不含已有连接交互，不是登录次数。</p>
            </details>
        </template>
        <template v-else-if="isRdp">
            <el-descriptions :column="1" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item label="登录失败次数"><el-tag type="info">不可观测</el-tag></el-descriptions-item>
            </el-descriptions>
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
        </template>
        <template v-else>
            <el-descriptions :column="2" border>
                <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
                <el-descriptions-item v-if="!isWindow" label="规则命中／阈值"
                    >{{ evidence.value ?? '未保存' }} / {{ evidence.threshold ?? '未保存' }}</el-descriptions-item
                >
                <el-descriptions-item v-if="!isWindow" label="规则配置窗口">{{ evidence.window_seconds ?? '未保存' }} 秒</el-descriptions-item>
                <el-descriptions-item v-if="!isWindow && typeof evidence.rule_observed_span_seconds === 'number'" label="实际规则覆盖范围">{{
                    ruleCoverage
                }}</el-descriptions-item>
                <el-descriptions-item v-if="sampleSeconds !== null" label="样本采集窗口">{{ sampleDuration }}</el-descriptions-item>
                <el-descriptions-item v-if="typeof sample.unique_targets === 'number'" label="样本目标数"
                    >{{ sample.unique_targets ?? '—' }}{{ sample.cardinality_capped ? '（计数可能截断）' : '' }}</el-descriptions-item
                >
                <el-descriptions-item v-if="typeof sample.tcp_attempts === 'number'" label="样本 TCP 建连尝试">{{
                    sample.tcp_attempts
                }}</el-descriptions-item>
                <el-descriptions-item v-if="typeof sample.synack_replies === 'number'" label="SYN-ACK 回复">{{
                    sample.synack_replies
                }}</el-descriptions-item>
                <el-descriptions-item v-if="replyRatio !== '不可计算'" label="握手回复比例">{{ replyRatio }}</el-descriptions-item>
                <el-descriptions-item v-if="typeof sample.completed_handshakes === 'number'" label="完整握手"
                    >{{ sample.completed_handshakes
                    }}<span v-if="completionRatio !== '不可计算'"> · {{ completionRatio }}</span></el-descriptions-item
                >
                <el-descriptions-item v-if="typeof sample.rst_replies === 'number'" label="配对 RST">{{ sample.rst_replies }}</el-descriptions-item>
                <el-descriptions-item v-if="typeof sample.mature_no_reply === 'number'" label="等待至少 3 秒仍无回复"
                    >{{ sample.mature_no_reply }}（非登录失败）</el-descriptions-item
                >
                <el-descriptions-item v-if="sample.ports?.length" label="目标端口">{{ sample.ports.join('、') }}</el-descriptions-item>
            </el-descriptions>

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
            </article>
        </template>
        <details class="evidence-notes">
            <summary>计数口径与证据限制</summary>
            <p v-if="isServiceTarget">
                按有效采集窗口合并去重目标 IP；同一 IP 重复连接只计一个目标，已有连接交互不增加目标数。服务端口不能确认实际协议，登录结果不可观测。
            </p>
            <p v-else-if="isRdp">宿主机旁路采集无法读取加密 RDP/TLS/NLA 登录结果；不可观测不等于失败 0 次。准确次数需要目标 Windows 认证日志。</p>
            <p v-else-if="record.kind === 'capture_degraded'">这是节点采集质量提醒；启用节点和阈值在检测规则配置。</p>
            <template v-else-if="sample.transport === 'UDP' || (isWindow && sample.udp_stats_version === 1)">
                <p v-if="isWindow">原始 UDP 总量包含 DNS；平均速率按实际采集时长计算，不是瞬时峰值。统计不产生异常告警。</p>
                <p v-else-if="isUdpRate">{{ udpCalculation }}</p>
                <p v-else>流数取单采集窗口最大值，不跨窗口累加，也不是每秒数量；源端口变化会形成另一条流。</p>
                <p>每窗口最多 8 个对端样本，样本数量不代表全部目标数。UDP 无握手；五元组数和双向包不能证明攻击或登录成功。</p>
            </template>
            <template v-else>
                <p v-if="record.kind === 'tcp_connection_burst'">
                    命中值为有效评估窗口内 SYN 建连尝试之和；握手、目标和端口来自单个样本窗口，不是 HTTP 请求或登录次数。
                </p>
                <p>目标表为最多 8 个有界样本，载荷可能含重传；域名和路径为部分可见线索，HTTPS 正文不可观测。</p>
            </template>
            <p v-if="sample.service_targets_capped || sample.cardinality_capped">统计存在截断，仅为观察下界，不能据此自动放行白名单。</p>
            <p v-if="!isRdp">未展示的统计项表示未采集或未保存，不能视为 0。</p>
            <p v-if="!isRdp && evidence.note">{{ evidence.note }}</p>
        </details>
    </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ record: Record<string, any>; windowStatistics?: boolean; compact?: boolean }>()
const evidence = computed(() => props.record.evidence || {})
const sample = computed(() => evidence.value.sample || evidence.value)
const analysis = computed(() => evidence.value.connection_analysis || {})
const endpoints = computed<any[]>(() => sample.value.outbound_endpoints || [])
const isRdp = computed(() => props.record.kind === 'rdp_connections')
const isServiceTarget = computed(() => ['ssh_target_spread', 'rdp_target_spread', 'ftp_target_spread'].includes(props.record.kind))
const serviceTargets = computed<string[]>(() =>
    Array.isArray(sample.value.targets) ? sample.value.targets.filter((target: unknown) => typeof target === 'string').slice(0, 128) : []
)
const isUdpRate = computed(() => props.record.kind === 'udp_packet_rate')
const isWindow = computed(() => props.windowStatistics === true)
const sampleSeconds = computed(() => {
    const start = parseTime(isWindow.value ? props.record.window_start : evidence.value.sample_window_start)
    const end = parseTime(isWindow.value ? props.record.window_end : evidence.value.sample_window_end)
    if (Number.isFinite(start) && Number.isFinite(end) && end > start) return (end - start) / 1000
    if (isWindow.value) return null
    const seconds = sample.value.observed_seconds
    return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? seconds : null
})
function parseTime(value: unknown) {
    if (typeof value !== 'string' || !value) return Number.NaN
    const iso = value.replace(' ', 'T')
    return Date.parse(/(Z|[+-]\d{2}:\d{2})$/.test(iso) ? iso : iso + 'Z')
}
function countText(value: unknown) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value.toLocaleString() : '未采集'
}
function averageText(value: unknown, unit: string, scale = 1) {
    if (sampleSeconds.value === null || typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '不可计算'
    return `${((value / sampleSeconds.value) * scale).toFixed(unit === 'Mbps' ? 2 : 1)} ${unit}`
}
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
    const startText = isWindow.value ? props.record.window_start : e.sample_window_start
    const endText = isWindow.value ? props.record.window_end : e.sample_window_end
    const start = parseTime(startText)
    const end = parseTime(endText)
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return sampleSeconds.value === null ? '未保存' : `${sampleSeconds.value} 秒`
    return `${((end - start) / 1000).toFixed(3).replace(/\.?0+$/, '')} 秒；${timeText(startText)} 至 ${timeText(endText)}`
})
function timeText(value: string) {
    const date = new Date(parseTime(value))
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
.evidence-notes {
    margin-top: 14px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.evidence-notes summary {
    cursor: pointer;
}
</style>
