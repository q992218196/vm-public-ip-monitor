<template>
    <section class="review-report">
        <div class="report-heading">
            <h3>IP 审核报告</h3>
            <el-button @click="exportReport">导出审核报告</el-button>
        </div>
        <TrafficEvidence v-if="rdpOnly" :record="{ kind: 'rdp_connections', ip: report.event.ip }" />
        <template v-else>
            <el-alert
                :title="report.conclusion + ' · 自动证据评估，需人工确认'"
                :type="report.category === 'strong_anomaly' ? 'warning' : 'info'"
                :closable="false"
            />
            <el-alert v-if="report.event.reopen_reason" :title="'重新复核原因：' + report.event.reopen_reason" type="warning" :closable="false" />
            <p>{{ report.scope }}</p>
            <el-descriptions :column="2" border>
                <el-descriptions-item label="采集窗口"
                    >{{ report.timeline.length }}（新版配对统计 {{ report.totals.paired_windows }}）</el-descriptions-item
                >
                <el-descriptions-item label="TCP 发起">{{ report.totals.attempts }}</el-descriptions-item>
                <el-descriptions-item label="完整握手比例">{{ completionRatio }} · 仅新版窗口</el-descriptions-item>
                <el-descriptions-item label="观察流量 出／入">{{ report.totals.bytes_out }} / {{ report.totals.bytes_in }} B</el-descriptions-item>
            </el-descriptions>
            <div class="report-reasons">
                <article>
                    <h4>判断理由</h4>
                    <ul>
                        <li v-for="text in report.reasons" :key="text">{{ text }}</li>
                    </ul>
                </article>
                <article>
                    <h4>正常业务的可能解释</h4>
                    <ul>
                        <li v-for="text in report.normal_explanations" :key="text">{{ text }}</li>
                    </ul>
                </article>
            </div>
            <template v-if="report.udp_totals?.windows">
                <h4>UDP 证据（观察窗口累计）</h4>
                <p>
                    窗口 {{ report.udp_totals.windows }} · 出站流 {{ report.udp_totals.flows }} · 包数 出／入 {{ report.udp_totals.packets_out }} /
                    {{ report.udp_totals.packets_in }} · 字节 出／入 {{ report.udp_totals.bytes_out }} / {{ report.udp_totals.bytes_in }} B
                </p>
                <p>
                    不同窗口的同一五元组会重复计入累计流数；UDP 无握手，服务回复也可能计入，不等于新建连接或攻击。{{
                        report.udp_totals.capped ? '目标样本截断或状态达到限额。' : ''
                    }}
                </p>
                <el-table :data="report.udp_targets || []" border size="small" max-height="420">
                    <el-table-column prop="peer_ip" label="目标 IP" min-width="150" />
                    <el-table-column prop="peer_port" label="端口" width="90" />
                    <el-table-column prop="flows" label="出站流数" width="100" />
                    <el-table-column label="包数 出／入" min-width="130"
                        ><template #default="scope">{{ scope.row.packets_out }} / {{ scope.row.packets_in }}</template></el-table-column
                    >
                    <el-table-column label="字节 出／入" min-width="160"
                        ><template #default="scope">{{ scope.row.bytes_out }} / {{ scope.row.bytes_in }} B</template></el-table-column
                    >
                </el-table>
            </template>
            <h4>TCP 发起数量趋势</h4>
            <svg v-if="report.timeline.length" viewBox="0 0 800 130" class="trend" role="img" aria-label="事件内 TCP 发起次数趋势，按实际时间定位">
                <line x1="20" y1="110" x2="780" y2="110" stroke="currentColor" opacity="0.2" />
                <polyline
                    v-for="(segment, index) in trendSegments"
                    :key="index"
                    :points="segment"
                    fill="none"
                    stroke="var(--el-color-primary)"
                    stroke-width="2"
                />
                <circle v-for="(point, index) in points" :key="index" :cx="point.x" :cy="point.y" r="3" fill="var(--el-color-primary)">
                    <title>{{ time(report.timeline[index].end) }}：{{ report.timeline[index].attempts }} 次</title>
                </circle>
                <text x="20" y="12" fill="currentColor" font-size="11">最大值 {{ maxAttempts }}</text>
            </svg>
            <p v-if="report.timeline.length">
                {{ time(report.timeline[0].start) }} 至 {{ time(report.timeline[report.timeline.length - 1].end) }}；空白时间没有补造数据。
            </p>
            <h4>主要目标连接样本</h4>
            <el-table :data="report.targets" border size="small" max-height="420">
                <el-table-column label="目标 IP / 端口" min-width="180"
                    ><template #default="scope">{{ scope.row.peer_ip }}:{{ scope.row.peer_port }}</template></el-table-column
                >
                <el-table-column prop="attempts" label="发起" width="75" />
                <el-table-column label="握手 / RST" width="115"
                    ><template #default="scope">{{
                        scope.row.paired_samples ? scope.row.completed + ' / ' + scope.row.rst : '未采集'
                    }}</template></el-table-column
                >
                <el-table-column label="载荷 出／入" min-width="160"
                    ><template #default="scope">{{ scope.row.payload_out }} / {{ scope.row.payload_in }} B</template></el-table-column
                >
                <el-table-column label="最长观察跨度" min-width="125"
                    ><template #default="scope">{{
                        scope.row.paired_samples ? (scope.row.max_observed_span_ms / 1000).toFixed(1) + ' 秒' : '未采集'
                    }}</template></el-table-column
                >
            </el-table>
            <h4>多端口访问目标</h4>
            <el-table :data="report.port_targets" border size="small" max-height="300">
                <el-table-column prop="peer_ip" label="目标 IP" min-width="160" /><el-table-column prop="port_count" label="端口数下界" width="110" />
                <el-table-column label="端口样本" min-width="220"
                    ><template #default="scope"
                        >{{ scope.row.ports.join('、') }}{{ scope.row.truncated ? '（有截断）' : '' }}</template
                    ></el-table-column
                >
            </el-table>
            <h4>可见请求线索</h4>
            <p v-if="!report.request_hints.length">没有可见 HTTP / SNI 样本，不代表没有网站请求。</p>
            <article v-for="(hint, index) in report.request_hints" :key="index" class="hint">
                <p>{{ hint.peer_ip }}:{{ hint.peer_port }} · {{ hint.scheme }} · {{ hint.host || '无域名线索' }}</p>
                <p v-if="hint.http_path">{{ hint.http_method }} {{ hint.http_path }} · 参数名称：{{ (hint.query_keys || []).join('、') || '无' }}</p>
            </article>
            <h4>证据缺口与限制</h4>
            <ul>
                <li v-for="text in report.evidence_gaps" :key="text">{{ text }}</li>
            </ul>
            <h4>建议核实事项</h4>
            <ol>
                <li v-for="text in report.next_steps" :key="text">{{ text }}</li>
            </ol>
            <el-collapse
                ><el-collapse-item title="逐窗口数据与采集质量" name="windows"
                    ><el-table :data="report.timeline" border size="small" max-height="360">
                        <el-table-column label="窗口结束" min-width="170"
                            ><template #default="scope">{{ time(scope.row.end) }}</template></el-table-column
                        >
                        <el-table-column prop="attempts" label="发起" /><el-table-column label="握手"
                            ><template #default="scope">{{ scope.row.completed ?? '未采集' }}</template></el-table-column
                        >
                        <el-table-column label="RST"
                            ><template #default="scope">{{ scope.row.rst ?? '未采集' }}</template></el-table-column
                        >
                        <el-table-column label="内核 / 状态丢弃" min-width="145"
                            ><template #default="scope"
                                >{{ scope.row.kernel_drops ?? '未知' }} / {{ scope.row.state_dropped ?? '未知' }}</template
                            ></el-table-column
                        >
                    </el-table></el-collapse-item
                ></el-collapse
            >
        </template>
    </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import TrafficEvidence from './TrafficEvidence.vue'
const props = defineProps<{ report: any }>()
const rdpOnly = computed(() => props.report.event.kinds?.length === 1 && props.report.event.kinds[0] === 'rdp_connections')
function time(value: string) {
    const raw = String(value).replace(' ', 'T')
    return new Date(/(Z|[+-]\d{2}:\d{2})$/.test(raw) ? raw : raw + 'Z').toLocaleString()
}
const completionRatio = computed(() =>
    props.report.totals.paired_attempts ? ((100 * props.report.totals.completed) / props.report.totals.paired_attempts).toFixed(1) + '%' : '不可计算'
)
function stamp(value: string) {
    const raw = String(value).replace(' ', 'T')
    return Date.parse(/(Z|[+-]\d{2}:\d{2})$/.test(raw) ? raw : raw + 'Z')
}
const maxAttempts = computed(() => Math.max(1, ...props.report.timeline.map((row: any) => row.attempts)))
const points = computed(() => {
    const rows = props.report.timeline
    const begin = rows.length ? stamp(rows[0].end) : 0
    const end = rows.length ? stamp(rows[rows.length - 1].end) : 0
    return rows.map((row: any) => ({
        x: 20 + (760 * (stamp(row.end) - begin)) / Math.max(1, end - begin),
        y: 110 - (90 * row.attempts) / maxAttempts.value,
    }))
})
const trendSegments = computed(() => {
    const segments: string[][] = [[]]
    points.value.forEach((point: any, index: number) => {
        if (index && stamp(props.report.timeline[index].start) - stamp(props.report.timeline[index - 1].end) > 1000) segments.push([])
        segments[segments.length - 1].push(`${point.x},${point.y}`)
    })
    return segments.map((segment) => segment.join(' '))
})
function exportReport() {
    const r = props.report
    const text = [
        'IP 审核报告',
        `事件 #${r.event.id} · ${r.event.ip || r.event.node_name}`,
        `自动评估：${r.conclusion}（不代表已确认违规）`,
        `人工状态：${r.event.status}`,
        `审核依据：${r.event.review_notes || '尚未填写'}`,
        r.scope,
        '判断理由',
        ...r.reasons,
        '正常业务的可能解释',
        ...r.normal_explanations,
        '证据缺口',
        ...r.evidence_gaps,
        '建议核实',
        ...r.next_steps,
        '结构化数据',
        JSON.stringify(r, null, 2),
    ].join('\n')
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `event-${r.event.id}-review.txt`
    anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>
<style scoped>
.review-report {
    margin-top: 20px;
    padding: 18px;
    background: var(--el-fill-color-extra-light);
    border-radius: 10px;
}
.report-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
}
.report-reasons {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}
p,
li {
    line-height: 1.8;
    overflow-wrap: anywhere;
}
.trend {
    width: 100%;
    height: auto;
    max-height: 180px;
}
.hint {
    padding: 8px 12px;
    background: var(--el-fill-color-light);
    margin-bottom: 8px;
    border-radius: 6px;
}
</style>
