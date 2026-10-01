<template>
    <div class="default-main event-page">
        <div class="heading">
            <div>
                <h2>告警中心</h2>
                <p>同节点、IP 的持续行为合并为事件。证据按需加载，抓包后可申请手动 AI 分析。</p>
            </div>
            <div>
                <el-button v-if="isAdmin && selected.length" type="primary" @click="openReview(selected)"
                    >处理所选 {{ selected.length }} 条</el-button
                >
                <el-button :loading="exporting" @click="exportPage">导出本页 CSV</el-button
                ><el-button :loading="loading" @click="load">刷新</el-button>
            </div>
        </div>
        <el-card shadow="never">
            <div class="filters">
                <el-input v-model="filters.search" placeholder="告警标题" clearable @keyup.enter="search" @clear="search" />
                <el-input v-model="filters.ip" placeholder="完整公网 IP" clearable @keyup.enter="search" @clear="search" />
                <el-select v-model="filters.node_id" placeholder="全部节点" clearable filterable @change="search"
                    ><el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id"
                /></el-select>
                <el-select v-model="filters.status" placeholder="全部状态" clearable @change="search"
                    ><el-option v-for="(statusLabel, value) in statuses" :key="value" :value="value" :label="statusLabel"
                /></el-select>
                <el-select v-model="filters.severity" placeholder="全部级别" clearable @change="search"
                    ><el-option label="高" value="high" /><el-option label="中" value="medium" /><el-option label="低" value="low"
                /></el-select>
                <el-button type="primary" :loading="loading" @click="search">查询</el-button>
                <el-select v-model="filters.assessment_category" placeholder="全部证据结论" clearable @change="search"
                    ><el-option label="一般行为提醒" value="behavior_notice" /><el-option label="疑似异常，待复核" value="needs_review" /><el-option
                        label="强异常证据，优先复核"
                        value="strong_anomaly"
                /></el-select>
            </div>
            <div class="columns">
                <el-popover placement="bottom-end" trigger="click" :width="220"
                    ><template #reference><el-button>显示字段</el-button></template>
                    <el-checkbox-group v-model="visible"
                        ><el-checkbox v-for="column in columns" :key="column.key" :label="column.label" :value="column.key"
                    /></el-checkbox-group>
                </el-popover>
            </div>
            <el-table v-loading="loading" :data="rows" border stripe @selection-change="selection" @sort-change="sort">
                <el-table-column v-if="isAdmin" type="selection" width="45" />
                <el-table-column
                    v-for="column in columns.filter((c) => visible.includes(c.key))"
                    :key="column.key"
                    :prop="column.key"
                    :label="column.label"
                    :sortable="column.sort ? 'custom' : false"
                    :min-width="column.width || 120"
                    show-overflow-tooltip
                >
                    <template #default="scope">
                        <el-button
                            v-if="['title', 'ip'].includes(column.key)"
                            link
                            type="primary"
                            @click="filterBy(column.key, scope.row[column.key])"
                            >{{ scope.row[column.key] || '—' }}</el-button
                        >
                        <el-tag
                            v-else-if="['severity', 'status', 'assessment_category'].includes(column.key)"
                            :type="color(scope.row[column.key])"
                            class="clickable"
                            @click="filterBy(column.key, scope.row[column.key])"
                            >{{ label(scope.row[column.key]) }}</el-tag
                        >
                        <span v-else-if="column.key.endsWith('_at')">{{ time(scope.row[column.key]) }}</span
                        ><span v-else>{{ scope.row[column.key] }}</span>
                    </template>
                </el-table-column>
                <el-table-column label="操作" fixed="right" min-width="160"
                    ><template #default="scope"
                        ><el-button link type="primary" @click="openDetail(scope.row.id)">详情与证据</el-button
                        ><el-button v-if="isAdmin" link type="warning" @click="whitelist(scope.row.id)">加入白名单</el-button></template
                    ></el-table-column
                >
            </el-table>
            <el-pagination
                v-model:current-page="page"
                v-model:page-size="limit"
                :page-sizes="[25, 50, 100, 200, 500]"
                :total="total"
                layout="total,sizes,prev,pager,next,jumper"
                @current-change="load"
                @size-change="search"
            />
        </el-card>
        <el-drawer v-model="detailOpen" title="事件报告与证据" size="min(1050px, 95vw)" @closed="closeDetail">
            <div v-loading="detailLoading">
                <el-alert v-if="detailError" type="error" :title="detailError" :closable="false" />
                <template v-if="detail?.event">
                    <h3>{{ detail.event.title }} · {{ detail.event.ip || detail.event.node_name }}</h3>
                    <el-descriptions border :column="2"
                        ><el-descriptions-item label="状态"
                            ><el-tag :type="color(detail.event.status)">{{ label(detail.event.status) }}</el-tag></el-descriptions-item
                        ><el-descriptions-item label="级别">{{ label(detail.event.severity) }}</el-descriptions-item
                        ><el-descriptions-item label="观察节点">{{ detail.event.node_name }}</el-descriptions-item
                        ><el-descriptions-item label="触发次数">{{ detail.event.occurrences }}</el-descriptions-item
                        ><el-descriptions-item label="首次观察">{{ time(detail.event.first_seen_at) }}</el-descriptions-item
                        ><el-descriptions-item label="最后观察">{{ time(detail.event.last_seen_at) }}</el-descriptions-item></el-descriptions
                    >
                    <p>{{ detail.event.review_notes }}</p>
                    <el-alert
                        v-if="detail.event.reopen_reason"
                        :title="'需要重新复核：' + detail.event.reopen_reason"
                        type="warning"
                        :closable="false"
                    />
                    <el-alert :title="qualityText" type="info" :closable="false" />
                    <div v-if="isAdmin" class="actions">
                        <el-button @click="openReview([detail.event.id])">人工审核</el-button
                        ><el-button type="warning" @click="whitelist(detail.event.id)">加入白名单</el-button
                        ><el-select v-model="snaplen" class="capture-length"
                            ><el-option :value="2048" label="每包前 2048 字节" /><el-option
                                :value="65535"
                                label="完整包（最多 65535 字节）" /></el-select
                        ><el-button type="primary" :loading="capturing" :disabled="!detail.event.ip" @click="capture">申请定向抓包</el-button>
                    </div>
                    <p>抓包只记录申请后的流量：最长 60 秒、32 MiB；同一节点同时采集一个 IP。原始文件可能包含明文请求数据，下载仅限管理员。</p>
                    <div v-loading="reviewReportLoading">
                        <EventReviewReport v-if="reviewReport" :report="reviewReport" /><el-alert
                            v-if="reviewReportError"
                            :title="reviewReportError"
                            type="error"
                            :closable="false"
                        />
                    </div>
                    <h3>规则证据</h3>
                    <el-collapse
                        ><el-collapse-item v-for="alert in detail.alerts" :key="alert.id" :name="alert.id" :title="alert.title"
                            ><TrafficEvidence :record="{ ...alert, ip: detail.event.ip }" />
                            <details>
                                <summary>原始结构化证据</summary>
                                <pre>{{ JSON.stringify(alert.evidence, null, 2) }}</pre>
                            </details></el-collapse-item
                        ></el-collapse
                    >
                    <h3>PCAP 抓包留存</h3>
                    <el-table :data="detail.captures" border
                        ><el-table-column label="申请时间" min-width="150"
                            ><template #default="scope">{{ time(scope.row.created_at) }}</template></el-table-column
                        ><el-table-column label="状态" width="100"
                            ><template #default="scope">{{ label(scope.row.status) }}</template></el-table-column
                        ><el-table-column label="大小／截断／丢弃" min-width="130"
                            ><template #default="scope"
                                >{{ (scope.row.bytes / 1048576).toFixed(2) }} MiB / {{ scope.row.metadata?.snaplen_truncated ?? '—' }} /
                                {{ scope.row.metadata?.queue_drops ?? '—' }}</template
                            ></el-table-column
                        ><el-table-column label="操作" min-width="150"
                            ><template #default="scope"
                                ><el-button
                                    v-if="isAdmin && scope.row.status === 'uploaded'"
                                    link
                                    type="primary"
                                    :loading="downloading === scope.row.id"
                                    @click="download(scope.row)"
                                    >下载 PCAP</el-button
                                ><el-button v-if="scope.row.status === 'uploaded'" link type="primary" @click="openCaptureReport(scope.row.id)"
                                    >抓包分析</el-button
                                ><el-button
                                    v-if="isAdmin && scope.row.status === 'uploaded'"
                                    link
                                    type="primary"
                                    :loading="requestingAi === scope.row.id"
                                    @click="requestAi(scope.row)"
                                    >AI 分析</el-button
                                ><span v-if="scope.row.last_error">{{ scope.row.last_error }}</span></template
                            ></el-table-column
                        ></el-table
                    >
                    <h3>手动 AI 分析</h3>
                    <el-table :data="detail.analyses" border
                        ><el-table-column label="申请时间"
                            ><template #default="scope">{{ time(scope.row.created_at) }}</template></el-table-column
                        ><el-table-column label="状态"
                            ><template #default="scope">{{ label(scope.row.status) }} {{ scope.row.last_error }}</template></el-table-column
                        ><el-table-column label="操作"
                            ><template #default="scope"
                                ><el-button link type="primary" @click="openReport(scope.row.id)">查看报告</el-button></template
                            ></el-table-column
                        ></el-table
                    >
                </template>
            </div>
        </el-drawer>
        <el-dialog v-model="reviewOpen" title="人工审核" width="min(520px, 95vw)"
            ><el-select v-model="reviewStatus"><el-option v-for="(text, value) in statuses" :key="value" :label="text" :value="value" /></el-select
            ><el-input v-model="reviewNotes" type="textarea" :rows="4" maxlength="2000" placeholder="业务核查依据与处理说明" /><template #footer
                ><el-button type="primary" :loading="reviewing" @click="review">保存审核结果</el-button></template
            ></el-dialog
        >
        <el-dialog v-model="reportOpen" title="AI 证据分析报告" width="min(950px, 95vw)"
            ><div v-loading="reportLoading">
                <template v-if="report"
                    ><el-alert title="AI 报告是辅助意见；请结合原始证据人工判断。" type="info" :closable="false" />
                    <p>{{ label(report.status) }} {{ report.last_error }}</p>
                    <p>模型：{{ report.model }} · 申请人 ID：{{ report.requested_by }} · 用量：{{ report.usage?.total_tokens ?? '未返回' }} tokens</p>
                    <pre>{{ report.report || '报告尚未生成' }}</pre>
                    <details>
                        <summary>发送给 AI 的解析证据</summary>
                        <pre>{{ JSON.stringify(report.evidence, null, 2) }}</pre>
                    </details></template
                >
            </div></el-dialog
        >
        <el-dialog v-model="captureReportOpen" title="主控抓包分析（不调用 AI）" width="min(950px, 95vw)">
            <div v-loading="captureReportLoading" v-if="captureReport">
                <p>SHA256：{{ captureReport.sha256 }}</p>
                <p v-if="!captureReport.summary">解析尚未完成，或解析失败：{{ captureReport.last_error || '稍后重新打开查看' }}</p>
                <template v-else>
                    <el-alert
                        title="未观察到回复不等于连接失败。仅覆盖抓包时间段，不能直接解密 HTTPS 或确定伪装代理协议。"
                        type="info"
                        :closable="false"
                    />
                    <el-descriptions border :column="2">
                        <el-descriptions-item label="捕获包数">{{ captureReport.summary.matched_packets }}</el-descriptions-item>
                        <el-descriptions-item label="出站目标数">{{ captureReport.summary.unique_outbound_targets }}</el-descriptions-item>
                        <el-descriptions-item label="SYNACK 回复流">{{ captureReport.summary.synack_flows }}</el-descriptions-item>
                        <el-descriptions-item label="完成握手流">{{ captureReport.summary.completed_handshakes }}</el-descriptions-item>
                        <el-descriptions-item label="RST 回复流">{{ captureReport.summary.rst_reply_flows }}</el-descriptions-item>
                        <el-descriptions-item label="未观察到回复流">{{ captureReport.summary.no_reply_observed_flows }}</el-descriptions-item>
                        <el-descriptions-item label="单目标最多端口">{{ captureReport.summary.max_ports_per_target }}</el-descriptions-item>
                        <el-descriptions-item label="摘要触及上限">{{
                            captureReport.summary.summary_capped ? '是，统计为下界' : '否'
                        }}</el-descriptions-item>
                    </el-descriptions>
                    <el-table :data="captureReport.summary.flow_samples" border>
                        <el-table-column label="目标" min-width="150"
                            ><template #default="scope">{{ scope.row.peer_ip }}:{{ scope.row.peer_port }}</template></el-table-column
                        >
                        <el-table-column prop="transport" label="传输" width="65" />
                        <el-table-column prop="syn_out" label="SYN 包数" width="85" />
                        <el-table-column label="握手／RST" min-width="100"
                            ><template #default="scope"
                                >{{ scope.row.handshake_completed ? '完成' : '未完整观察' }} / {{ scope.row.rst_in ? '有' : '无' }}</template
                            ></el-table-column
                        >
                        <el-table-column label="可见请求头／SNI" min-width="200"
                            ><template #default="scope">{{
                                scope.row.http
                                    ? [scope.row.http.method, scope.row.http.host, scope.row.http.path].join(' ')
                                    : scope.row.tls_client_hello_sni
                                      ? 'SNI：' + scope.row.tls_client_hello_sni
                                      : '—'
                            }}</template></el-table-column
                        >
                    </el-table>
                    <details>
                        <summary>完整摘要与采集质量</summary>
                        <pre>{{ JSON.stringify(captureReport, null, 2) }}</pre>
                    </details>
                </template>
            </div>
        </el-dialog>
    </div>
</template>
<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import createAxios from '/@/utils/axios'
import TrafficEvidence from './TrafficEvidence.vue'
import EventReviewReport from './EventReviewReport.vue'
const statuses: Record<string, string> = { open: '待处理', acknowledged: '观察中', normal: '已核查正常', resolved: '已处理' }
const names: Record<string, string> = {
    ...statuses,
    high: '高',
    medium: '中',
    low: '低',
    behavior_notice: '一般行为提醒',
    needs_review: '疑似异常，待复核',
    strong_anomaly: '强异常证据，优先复核',
    pending: '等待执行',
    leased: '抓包中',
    uploaded: '已留存',
    expired: '已过期',
    running: '分析中',
    completed: '已完成',
    failed: '失败',
}
const columns = [
    { key: 'title', label: '告警', sort: true, width: 200 },
    { key: 'ip', label: '公网 IP', sort: true, width: 150 },
    { key: 'node_name', label: '观察节点' },
    { key: 'severity', label: '级别', sort: true },
    { key: 'assessment_category', label: '证据结论', width: 200 },
    { key: 'status', label: '状态', sort: true },
    { key: 'occurrences', label: '触发次数', sort: true },
    { key: 'first_seen_at', label: '首次观察', width: 165 },
    { key: 'last_seen_at', label: '最后观察', sort: true, width: 165 },
]
const visible = ref(columns.filter((c) => c.key !== 'first_seen_at').map((c) => c.key))
const rows = ref<any[]>([]),
    nodes = ref<any[]>([]),
    selected = ref<number[]>([]),
    isAdmin = ref(false),
    loading = ref(false),
    total = ref(0),
    page = ref(1),
    limit = ref(25),
    exporting = ref(false)
const filters = reactive({
    search: '',
    ip: '',
    node_id: '',
    status: 'open',
    severity: '',
    assessment_category: '',
    sort: 'last_seen_at',
    direction: 'desc',
})
const detailOpen = ref(false),
    detailLoading = ref(false),
    detailError = ref(''),
    detail = ref<any>(null),
    detailId = ref(0),
    snaplen = ref(2048),
    capturing = ref(false),
    downloading = ref(''),
    requestingAi = ref('')
const reviewOpen = ref(false),
    reviewStatus = ref('normal'),
    reviewNotes = ref(''),
    reviewIds = ref<number[]>([]),
    reviewing = ref(false),
    reportOpen = ref(false),
    reportLoading = ref(false),
    report = ref<any>(null)
const captureReportOpen = ref(false),
    captureReportLoading = ref(false),
    captureReport = ref<any>(null)
const reviewReport = ref<any>(null),
    reviewReportLoading = ref(false),
    reviewReportError = ref('')
let poll: ReturnType<typeof setTimeout> | undefined
let generation = 0,
    detailGeneration = 0
const qualityText = computed(() => {
    const q = detail.value?.event?.quality || {}
    return `采集窗口质量：内核丢弃 ${q.kernel_drops ?? '未知'}，状态丢弃 ${q.state_dropped ?? '未知'}，重组丢弃 ${q.reassembly_dropped ?? '未知'}。统计来自 ${time(q.observed_at)}，不等于 PCAP 采集全程；未看到回复不能直接证明失败。`
})
const api = (action: string, data: any = {}, method: 'get' | 'post' = 'get') =>
    createAxios({ url: '/admin/EventEvidence/' + action, method, ...(method === 'get' ? { params: data } : { data }) })
function label(value: string) {
    return names[value] || value
}
function color(value: string): 'danger' | 'warning' | 'success' | 'info' {
    return ['high', 'open', 'failed', 'strong_anomaly'].includes(value)
        ? 'danger'
        : ['medium', 'acknowledged', 'running', 'needs_review'].includes(value)
          ? 'warning'
          : ['normal', 'resolved', 'completed', 'uploaded'].includes(value)
            ? 'success'
            : 'info'
}
function time(value: any) {
    if (!value) return '—'
    const raw = String(value).replace(' ', 'T')
    const date = new Date(/(Z|[+-]\d{2}:\d{2})$/.test(raw) ? raw : raw + 'Z')
    return isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}
async function load() {
    const g = ++generation
    loading.value = true
    const params = { ...filters, page: page.value, limit: limit.value }
    try {
        const result = await api('index', params)
        if (g !== generation) return
        rows.value = result.data.list
        isAdmin.value = result.data.super
        selected.value = []
        api('count', params)
            .then((r) => {
                if (g === generation) total.value = r.data.total
            })
            .catch(() => {})
    } finally {
        if (g === generation) loading.value = false
    }
}
function search() {
    page.value = 1
    load()
}
function selection(value: any[]) {
    selected.value = value.map((r) => r.id)
}
function sort(value: any) {
    filters.sort = value.prop || 'last_seen_at'
    filters.direction = value.order === 'ascending' ? 'asc' : 'desc'
    search()
}
function filterBy(key: string, value: string) {
    if (key === 'title') filters.search = value
    else if (key === 'ip') filters.ip = value
    else if (key === 'severity') filters.severity = value
    else if (key === 'status') filters.status = value
    else if (key === 'assessment_category') filters.assessment_category = value
    search()
}
async function openDetail(id: number) {
    detailId.value = id
    detail.value = null
    reviewReport.value = null
    reviewReportError.value = ''
    detailOpen.value = true
    detailLoading.value = true
    detailError.value = ''
    await refreshDetail()
    detailLoading.value = false
}
async function refreshDetail() {
    clearTimeout(poll)
    const id = detailId.value,
        g = ++detailGeneration
    try {
        const r = await api('detail', { id })
        if (g !== detailGeneration || !detailOpen.value || detailId.value !== id) return
        detail.value = r.data
        loadReviewReport(id, g)
        if (
            r.data.captures.some((c: any) => ['pending', 'leased'].includes(c.status)) ||
            r.data.analyses.some((a: any) => ['pending', 'running'].includes(a.status))
        )
            poll = setTimeout(refreshProgress, 5000)
    } catch {
        if (g === detailGeneration) detailError.value = '证据加载失败，请关闭后重试'
    }
}
async function refreshProgress() {
    clearTimeout(poll)
    const id = detailId.value,
        g = detailGeneration
    try {
        const result = await api('progress', { id })
        if (!detailOpen.value || !detail.value || id !== detailId.value || g !== detailGeneration) return
        Object.assign(detail.value, result.data)
        if (
            result.data.captures.some((c: any) => ['pending', 'leased'].includes(c.status)) ||
            result.data.analyses.some((a: any) => ['pending', 'running'].includes(a.status))
        )
            poll = setTimeout(refreshProgress, 5000)
    } catch {
        /* The list and already loaded evidence remain available. */
    }
}
function closeDetail() {
    clearTimeout(poll)
    detailGeneration++
    detailId.value = 0
    detail.value = null
    reviewReportLoading.value = false
}
async function loadReviewReport(id: number, g: number) {
    reviewReportLoading.value = true
    try {
        const r = await api('reviewReport', { id })
        if (g === detailGeneration && detailOpen.value && id === detailId.value) reviewReport.value = r.data.report
    } catch {
        if (g === detailGeneration && detailOpen.value) reviewReportError.value = '审核报告加载失败；规则和抓包证据仍可查看'
    } finally {
        if (g === detailGeneration) reviewReportLoading.value = false
    }
}
function openReview(ids: number[]) {
    reviewIds.value = ids
    reviewNotes.value = ''
    reviewStatus.value = 'normal'
    reviewOpen.value = true
}
async function review() {
    reviewing.value = true
    try {
        await api('review', { ids: reviewIds.value, status: reviewStatus.value, notes: reviewNotes.value }, 'post')
        reviewOpen.value = false
        ElMessage.success('审核已保存')
        load()
        if (detailOpen.value) await refreshDetail()
    } finally {
        reviewing.value = false
    }
}
async function whitelist(id: number) {
    await ElMessageBox.confirm('将当前节点、IP、已命中的告警类型加入 30 天白名单。新类型仍会告警，原始证据保留。', '加入白名单', { type: 'warning' })
    await api('whitelist', { id }, 'post')
    ElMessage.success('已加入白名单')
    load()
    if (detailOpen.value) await refreshDetail()
}
async function capture() {
    capturing.value = true
    try {
        await api('capture', { id: detailId.value, snaplen: snaplen.value }, 'post')
        ElMessage.success('抓包任务已提交')
        await refreshProgress()
    } finally {
        capturing.value = false
    }
}
async function download(item: any) {
    downloading.value = item.id
    try {
        const blob = await createAxios<any, Promise<Blob>>({
            url: '/admin/EventEvidence/download',
            params: { id: item.id },
            responseType: 'blob',
            timeout: 60000,
        })
        if (blob.type.includes('json')) {
            ElMessage.error('下载失败，请重新登录后重试')
            return
        }
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = item.id + '.pcap'
        a.click()
        URL.revokeObjectURL(url)
    } finally {
        downloading.value = ''
    }
}
async function requestAi(item: any) {
    if (!detail.value.ai?.enabled) {
        ElMessage.info('请先在 AI 分析设置中配置并启用 DeepSeek')
        return
    }
    await ElMessageBox.confirm(
        `将此 PCAP 的解析证据摘要（IP、端口、握手、流量、可见明文请求头）发送到 ${detail.value.ai.endpoint}，模型 ${detail.value.ai.model}。原始 PCAP 不上传，API 调用可能产生费用，失败不会自动重试。`,
        '手动申请 AI 分析',
        { type: 'warning', confirmButtonText: '提交分析' }
    )
    requestingAi.value = item.id
    try {
        await api('requestAi', { capture_id: item.id }, 'post')
        ElMessage.success('分析已排队')
        await refreshProgress()
    } finally {
        requestingAi.value = ''
    }
}
async function openReport(id: number) {
    report.value = null
    reportOpen.value = true
    reportLoading.value = true
    try {
        const r = await api('analysis', { id })
        report.value = r.data.record
    } finally {
        reportLoading.value = false
    }
}
async function openCaptureReport(id: string) {
    captureReport.value = null
    captureReportOpen.value = true
    captureReportLoading.value = true
    try {
        const result = await api('captureSummary', { id })
        captureReport.value = result.data.record
    } finally {
        captureReportLoading.value = false
    }
}
async function exportPage() {
    exporting.value = true
    try {
        const keys = columns.map((c) => c.key)
        const cell = (v: any) =>
            '"' +
            String(v ?? '')
                .replace(/"/g, '""')
                .replace(/^[=+@-]/, "'$&") +
            '"'
        const csv =
            '\ufeff' +
            [
                columns.map((c) => cell(c.label)).join(','),
                ...rows.value.map((row) => keys.map((k) => cell(k.endsWith('_at') ? time(row[k]) : row[k])).join(',')),
            ].join('\r\n')
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
        const a = document.createElement('a')
        a.href = url
        a.download = '监控事件.csv'
        a.click()
        URL.revokeObjectURL(url)
    } finally {
        exporting.value = false
    }
}
onMounted(() => {
    createAxios({ url: '/admin/Monitor/nodes' }).then((r) => {
        nodes.value = r.data.list
        isAdmin.value = r.data.super
    })
    load()
})
onBeforeUnmount(() => {
    clearTimeout(poll)
    generation++
    detailGeneration++
})
</script>
<style scoped>
.heading {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.heading h2 {
    margin: 0;
}
.heading p {
    color: var(--el-text-color-secondary);
}
.filters,
.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 16px 0;
}
.filters .el-input,
.filters .el-select {
    width: 170px;
}
.capture-length {
    width: 220px;
}
.columns {
    text-align: right;
    margin: 14px 0;
}
.columns .el-checkbox {
    display: block;
}
.el-pagination {
    margin-top: 20px;
    flex-wrap: wrap;
}
.clickable {
    cursor: pointer;
}
pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.7;
    max-height: 65vh;
    overflow: auto;
}
.el-dialog .el-textarea {
    margin-top: 16px;
}
</style>
