<template>
    <div class="default-main monitor-page">
        <div class="monitor-heading">
            <div>
                <h2>{{ definition.title }}</h2>
                <p>监控数据按需读取，证据在打开单条详情时加载。</p>
            </div>
            <div class="monitor-heading-actions">
                <el-button v-if="canCreate" type="primary" @click="openEditor()">新增</el-button>
                <el-button v-if="resource === 'websites' && isAdmin" @click="manualOpen = true">添加已知网站</el-button>
                <el-button v-if="resource === 'alerts' && selected.length && isAdmin" type="primary" @click="bulkOpen = true"
                    >处理所选 {{ selected.length }} 条</el-button
                >
                <el-button v-if="['ips', 'websites', 'alerts'].includes(resource)" :loading="exporting" @click="exportCsv">导出 CSV</el-button>
                <el-button @click="load">刷新</el-button>
            </div>
        </div>

        <el-card shadow="never" class="monitor-card">
            <div class="monitor-filters">
                <el-input
                    v-if="definition.search"
                    v-model="filters.search"
                    :placeholder="definition.search"
                    clearable
                    @keyup.enter="resetAndLoad"
                    @clear="resetAndLoad"
                />
                <el-input
                    v-if="definition.ip"
                    v-model="filters.ip"
                    placeholder="完整公网 IP"
                    clearable
                    @keyup.enter="resetAndLoad"
                    @clear="resetAndLoad"
                />
                <el-select v-if="definition.node" v-model="filters.node" placeholder="全部节点" clearable filterable @change="resetAndLoad">
                    <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
                </el-select>
                <el-select v-if="definition.status" v-model="filters.status" placeholder="全部状态" clearable @change="resetAndLoad">
                    <el-option v-for="item in definition.status" :key="item.value" :label="item.label" :value="item.value" />
                </el-select>
                <el-select v-if="resource === 'alerts'" v-model="filters.severity" placeholder="全部级别" clearable @change="resetAndLoad">
                    <el-option label="高" value="high" /><el-option label="中" value="medium" /><el-option label="低" value="low" />
                </el-select>
                <el-select v-if="resource === 'websites'" v-model="filters.review" placeholder="全部分类" clearable @change="resetAndLoad">
                    <el-option label="待人工复核" value="1" />
                </el-select>
                <el-button type="primary" :loading="loading" @click="resetAndLoad">查询</el-button>
            </div>

            <div class="monitor-column-control">
                <el-popover placement="bottom-end" trigger="click" :width="250">
                    <template #reference><el-button>显示字段</el-button></template>
                    <el-checkbox-group v-model="visibleKeys" class="monitor-column-list">
                        <el-checkbox v-for="column in definition.columns" :key="column.key" :label="column.label" :value="column.key" />
                    </el-checkbox-group>
                </el-popover>
            </div>
            <el-table
                :data="rows"
                v-loading="loading"
                border
                stripe
                table-layout="auto"
                @selection-change="(items: any[]) => (selected = items.map((item) => item.id))"
            >
                <el-table-column v-if="resource === 'alerts' && isAdmin" type="selection" width="48" />
                <el-table-column
                    v-for="column in visibleColumns"
                    :key="column.key"
                    :prop="column.key"
                    :label="column.label"
                    min-width="130"
                    show-overflow-tooltip
                >
                    <template #default="scope">
                        <el-tag v-if="column.key === 'status' || column.key === 'severity'" :type="tagType(scope.row[column.key])">{{
                            display(scope.row[column.key])
                        }}</el-tag>
                        <a
                            v-else-if="column.key === 'host' && resource === 'websites' && scope.row.host"
                            :href="websiteUrl(scope.row)"
                            target="_blank"
                            rel="noopener noreferrer"
                            >{{ scope.row.host }}</a
                        >
                        <span v-else>{{ display(scope.row[column.key]) }}</span>
                    </template>
                </el-table-column>
                <el-table-column label="操作" fixed="right" min-width="190">
                    <template #default="scope">
                        <el-button link type="primary" @click="openDetail(scope.row)">详情</el-button>
                        <el-button v-if="isAdmin && definition.edit" link type="primary" @click="openEditor(scope.row)">编辑</el-button>
                        <el-button
                            v-if="isAdmin && resource === 'websites'"
                            link
                            type="primary"
                            :loading="actionId === scope.row.id"
                            @click="probe(scope.row)"
                            >验证／截图</el-button
                        >
                        <el-button
                            v-if="isAdmin && resource === 'nodes'"
                            link
                            type="warning"
                            :loading="actionId === scope.row.id"
                            @click="nodeConfig(scope.row)"
                            >接入配置</el-button
                        >
                    </template>
                </el-table-column>
            </el-table>
            <div class="monitor-pagination">
                <span>{{ countLoading ? '总数统计中…' : countError ? '总数暂不可用' : '共 ' + total.toLocaleString() + ' 条' }}</span>
                <el-pagination
                    v-model:current-page="page"
                    v-model:page-size="limit"
                    :total="total"
                    :page-sizes="[10, 25, 50, 100, 200, 500]"
                    layout="sizes, prev, pager, next"
                    @current-change="load"
                    @size-change="resetAndLoad"
                />
            </div>
        </el-card>

        <el-drawer v-model="detailOpen" title="记录与证据" size="min(720px, 94vw)" destroy-on-close>
            <el-skeleton v-if="detailLoading" :rows="8" animated />
            <template v-else>
                <el-alert
                    v-if="resource === 'alerts' && detail?.kind === 'capture_degraded'"
                    type="warning"
                    :closable="false"
                    title="采集覆盖下降表示节点丢包或状态丢弃，统计可能不完整；不是 VM 异常流量证据。"
                />
                <div v-if="resource === 'websites' && detail?.screenshot_path" class="monitor-screenshot">
                    <el-button :loading="screenshotLoading" @click="loadScreenshot">查看截图</el-button>
                    <img v-if="screenshotData" :src="screenshotData" alt="网站验证截图" />
                </div>
                <pre class="monitor-evidence">{{ JSON.stringify(detail, null, 2) }}</pre>
            </template>
        </el-drawer>

        <el-dialog
            v-model="editorOpen"
            :title="editingId ? '编辑' + definition.title : '新增' + definition.title"
            width="min(620px, 94vw)"
            destroy-on-close
        >
            <el-skeleton v-if="editorLoading" :rows="6" animated />
            <el-form v-else label-position="top" @submit.prevent="save">
                <el-form-item v-for="field in definition.edit || []" :key="field.key" :label="field.label">
                    <el-switch v-if="field.type === 'switch'" v-model="form[field.key]" />
                    <el-select v-else-if="field.type === 'select'" v-model="form[field.key]" clearable filterable style="width: 100%">
                        <el-option v-for="item in field.options" :key="item.value" :label="item.label" :value="item.value" />
                    </el-select>
                    <el-select v-else-if="field.type === 'node'" v-model="form[field.key]" clearable filterable style="width: 100%">
                        <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
                    </el-select>
                    <el-date-picker
                        v-else-if="field.type === 'datetime'"
                        v-model="form[field.key]"
                        type="datetime"
                        value-format="YYYY-MM-DD HH:mm:ss"
                        style="width: 100%"
                    />
                    <el-input
                        v-else
                        v-model="form[field.key]"
                        :type="field.type === 'number' ? 'number' : field.type === 'textarea' ? 'textarea' : 'text'"
                        :rows="field.type === 'textarea' ? 5 : undefined"
                    />
                </el-form-item>
            </el-form>
            <template #footer
                ><el-button @click="editorOpen = false">取消</el-button
                ><el-button type="primary" :disabled="editorLoading" :loading="saving" @click="save">保存</el-button></template
            >
        </el-dialog>

        <el-dialog v-model="manualOpen" title="添加已知公网 IP 网站" width="min(520px, 94vw)">
            <el-form label-position="top">
                <el-form-item label="已登记公网 IP"><el-input v-model="manual.ip" placeholder="例如 203.0.113.10" /></el-form-item>
                <el-form-item label="端口"><el-input-number v-model="manual.port" :min="1" :max="65535" style="width: 100%" /></el-form-item>
                <el-form-item label="协议"
                    ><el-select v-model="manual.scheme" style="width: 100%"
                        ><el-option label="HTTPS" value="https" /><el-option label="HTTP" value="http" /></el-select
                ></el-form-item>
                <el-form-item label="域名（可留空）"><el-input v-model="manual.host" placeholder="example.com" /></el-form-item>
            </el-form>
            <template #footer
                ><el-button @click="manualOpen = false">取消</el-button
                ><el-button type="primary" :loading="saving" @click="addManual">添加并验证</el-button></template
            >
        </el-dialog>

        <el-dialog v-model="bulkOpen" title="批量处理告警" width="min(520px, 94vw)">
            <p>已选择 {{ selected.length }} 条，单次最多处理 500 条。</p>
            <el-select v-model="bulkStatus" style="width: 100%; margin-bottom: 12px"
                ><el-option label="已确认" value="acknowledged" /><el-option label="已解决" value="resolved" /><el-option
                    label="重新打开"
                    value="open"
            /></el-select>
            <el-input v-model="resolution" type="textarea" :rows="4" maxlength="4000" show-word-limit placeholder="填写处理记录" />
            <template #footer
                ><el-button @click="bulkOpen = false">取消</el-button
                ><el-button type="primary" :loading="saving" @click="bulkSave">确认处理</el-button></template
            >
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import createAxios from '/@/utils/axios'
import { useAdminInfo } from '/@/stores/adminInfo'

type Option = { label: string; value: string }
type Field = { key: string; label: string; type?: string; options?: Option[] }
type Definition = {
    title: string
    columns: Field[]
    edit?: Field[]
    create?: boolean
    search?: string
    ip?: boolean
    node?: boolean
    status?: Option[]
}
const col = (key: string, label: string): Field => ({ key, label })
const options = (values: Record<string, string>): Option[] => Object.entries(values).map(([value, label]) => ({ value, label }))
const definitions: Record<string, Definition> = {
    nodes: {
        title: '采集节点',
        search: '节点名称',
        create: true,
        columns: [
            col('name', '节点'),
            col('id', '节点 ID'),
            col('enabled', '启用'),
            col('cidrs', 'CIDR'),
            col('last_seen_at', '最近上报'),
            col('rss_mib', '进程内存 MiB'),
            col('kernel_drops', '窗口丢包'),
        ],
        edit: [
            col('name', '节点名称'),
            { ...col('enabled', '允许上报'), type: 'switch' },
            { ...col('cidrs', '公网 CIDR，每行一个'), type: 'textarea' },
            { ...col('interfaces', '采集接口，每行一个'), type: 'textarea' },
            { ...col('memory_soft_mib', '工作内存 MiB'), type: 'number' },
            { ...col('memory_hard_mib', '服务硬限额 MiB'), type: 'number' },
            { ...col('disk_limit_mib', 'Agent 目录预算 MiB'), type: 'number' },
            col('data_dir', 'Agent 数据目录'),
            { ...col('notes', '备注'), type: 'textarea' },
        ],
    },
    ips: {
        title: '公网 IP',
        search: '公网 IP',
        columns: [col('ip', '公网 IP'), col('version', 'IP 版本'), col('label', '归属标签'), col('last_seen_at', '最后观察')],
        edit: [col('label', '归属标签'), { ...col('notes', '备注'), type: 'textarea' }],
    },
    websites: {
        title: '网站资产',
        search: '域名前缀',
        ip: true,
        status: options({ observed: '待验证线索', candidate: '探测候选', verified: '已验证', failed: '失败' }),
        columns: [
            col('ip', '公网 IP'),
            col('host', '域名线索'),
            col('port', '端口'),
            col('scheme', '协议'),
            col('status', '验证状态'),
            col('title', '标题'),
            col('description', '网站描述'),
            col('category', '自动分类'),
            col('last_probed_at', '最近验证'),
        ],
        edit: [col('manual_category', '人工分类')],
    },
    alerts: {
        title: '告警中心',
        search: '告警标题',
        ip: true,
        node: true,
        status: options({ open: '待处理', acknowledged: '已确认', resolved: '已解决' }),
        columns: [
            col('title', '告警'),
            col('ip', '公网 IP'),
            col('node_name', '观察节点'),
            col('severity', '级别'),
            col('status', '状态'),
            col('occurrences', '触发次数'),
            col('last_seen_at', '最后触发'),
        ],
    },
    rules: {
        title: '检测规则',
        search: '规则名称',
        node: true,
        create: true,
        columns: [col('name', '规则'), col('kind', '类型'), col('threshold', '阈值'), col('window_seconds', '窗口秒'), col('enabled', '启用')],
        edit: [
            col('name', '规则名称'),
            {
                ...col('kind', '检测类型'),
                type: 'select',
                options: options({
                    horizontal_scan: '横向扫描',
                    vertical_scan: '端口扫描',
                    suspected_bruteforce: '认证端口重复连接',
                    single_target_attempts: '单目标高频连接',
                    tcp_connection_burst: 'TCP 连接突增',
                    egress_mbps: '出站 Mbps',
                    vpn_protocol: 'VPN 双向握手',
                    proxy_suspect: '疑似加密代理',
                }),
            },
            { ...col('threshold', '阈值'), type: 'number' },
            { ...col('window_seconds', '评估窗口秒'), type: 'number' },
            { ...col('cooldown_seconds', '告警合并窗口秒'), type: 'number' },
            { ...col('severity', '级别'), type: 'select', options: options({ low: '低', medium: '中', high: '高' }) },
            { ...col('node_id', '适用节点'), type: 'node' },
            { ...col('enabled', '启用'), type: 'switch' },
        ],
    },
    exclusions: {
        title: '维护与白名单',
        search: 'CIDR',
        node: true,
        create: true,
        columns: [col('cidr', '源公网 IP/CIDR'), col('reason', '原因'), col('node_id', '适用节点'), col('expires_at', '失效时间')],
        edit: [
            col('cidr', '源公网 IP/CIDR'),
            col('reason', '原因'),
            { ...col('expires_at', '失效时间'), type: 'datetime' },
            { ...col('node_id', '适用节点'), type: 'node' },
        ],
    },
    metrics: {
        title: '流量窗口',
        ip: true,
        node: true,
        columns: [
            col('ip', '公网 IP'),
            col('node_name', '观察节点'),
            col('bytes_out', '出站字节'),
            col('bytes_in', '入站字节'),
            col('tcp_attempts', 'TCP 发起次数'),
            col('window_end', '窗口结束'),
        ],
    },
    protocols: {
        title: '协议观察',
        ip: true,
        node: true,
        columns: [
            col('ip', '公网 IP'),
            col('node_name', '观察节点'),
            col('protocol', '协议线索'),
            col('peer_ip', '对端 IP'),
            col('local_port', '本地端口'),
            col('peer_port', '对端端口'),
            col('window_end', '窗口结束'),
        ],
    },
    tasks: {
        title: '网站探测任务',
        search: '域名',
        ip: true,
        status: options({ pending: '等待', leased: '执行中', done: '完成', failed: '失败' }),
        columns: [
            col('ip', '公网 IP'),
            col('host', '域名'),
            col('port', '端口'),
            col('status', '状态'),
            col('attempts', '尝试次数'),
            col('last_error', '最近错误'),
        ],
    },
    audit: { title: '审计日志', columns: [col('action', '操作'), col('subject', '对象'), col('created_at', '时间')] },
}
const route = useRoute()
const resource = computed(() => route.path.split('/').pop() || 'alerts')
const definition = computed(() => definitions[resource.value] || definitions.alerts)
const rows = ref<any[]>([])
const nodes = ref<{ id: string; name: string }[]>([])
const total = ref(0)
const page = ref(1)
const limit = ref(25)
const loading = ref(false)
const countLoading = ref(false)
const countError = ref(false)
let countKey = ''
let loadSequence = 0
let countSequence = 0
const saving = ref(false)
const exporting = ref(false)
const isAdmin = ref(false)
const actionId = ref<number | string | null>(null)
const selected = ref<number[]>([])
const filters = reactive({ search: '', ip: '', node: '', status: '', severity: '', review: '' })
const detail = ref<any>(null)
const detailOpen = ref(false)
const detailLoading = ref(false)
const screenshotLoading = ref(false)
const screenshotData = ref('')
const editorOpen = ref(false)
const editorLoading = ref(false)
const editingId = ref<number | string | null>(null)
const form = reactive<Record<string, any>>({})
const bulkOpen = ref(false)
const bulkStatus = ref('acknowledged')
const resolution = ref('')
const manualOpen = ref(false)
const manual = reactive({ ip: '', port: 443, scheme: 'https', host: '' })
const visibleKeys = ref<string[]>([])
const visibleColumns = computed(() => definition.value.columns.filter((column) => visibleKeys.value.includes(column.key)))
const canCreate = computed(() => isAdmin.value && definition.value.create)

function request(action: string, method: 'get' | 'post', data: Record<string, any> = {}) {
    return createAxios({ url: '/admin/Monitor/' + action, method, ...(method === 'get' ? { params: data } : { data }) })
}
function resetAndLoad() {
    page.value = 1
    countKey = ''
    load()
}
async function load() {
    const sequence = ++loadSequence
    const query = { resource: resource.value, ...filters }
    const key = JSON.stringify(query)
    if (key !== countKey) {
        countKey = key
        const countRequest = ++countSequence
        countLoading.value = true
        countError.value = false
        void request('count', 'get', query)
            .then((result) => {
                if (countRequest === countSequence) total.value = Number(result.data.total)
            })
            .catch(() => {
                if (countRequest === countSequence) countError.value = true
            })
            .finally(() => {
                if (countRequest === countSequence) countLoading.value = false
            })
    }
    loading.value = true
    try {
        const result = await request('index', 'get', { ...query, page: page.value, limit: limit.value })
        if (sequence !== loadSequence) return
        rows.value = result.data.list
        isAdmin.value = !!result.data.super
    } finally {
        if (sequence === loadSequence) loading.value = false
    }
}
async function loadNodes() {
    const result = await request('nodes', 'get')
    nodes.value = result.data.list
}
watch(
    resource,
    () => {
        page.value = 1
        countKey = ''
        selected.value = []
        visibleKeys.value = definition.value.columns.filter((column) => column.key !== 'description').map((column) => column.key)
        Object.assign(filters, { search: '', ip: '', node: '', status: '', severity: '', review: '' })
        load()
    },
    { immediate: true }
)
loadNodes()

function display(value: any): string {
    if (value === null || value === undefined || value === '') return '—'
    if (typeof value === 'boolean') return value ? '是' : '否'
    if (Array.isArray(value)) return value.join('、')
    if (typeof value === 'object') return JSON.stringify(value)
    const labels: Record<string, string> = {
        open: '待处理',
        acknowledged: '已确认',
        resolved: '已解决',
        observed: '待验证',
        candidate: '候选',
        verified: '已验证',
        failed: '失败',
        pending: '等待',
        leased: '执行中',
        done: '完成',
        high: '高',
        medium: '中',
        low: '低',
    }
    if (labels[String(value)]) return labels[String(value)]
    return String(value)
}
function websiteUrl(row: any): string {
    const host = String(row.host || row.ip || '')
    const authority = host.includes(':') ? '[' + host + ']' : host
    return String(row.scheme || 'http') + '://' + authority + ':' + Number(row.port) + '/'
}
function tagType(value: string) {
    if (['open', 'failed', 'high'].includes(value)) return 'danger'
    if (['acknowledged', 'candidate', 'medium', 'pending'].includes(value)) return 'warning'
    if (['resolved', 'verified', 'done', 'low'].includes(value)) return 'success'
    return 'info'
}
async function openDetail(row: any) {
    detailOpen.value = true
    detailLoading.value = true
    detail.value = null
    screenshotData.value = ''
    try {
        const result = await request('detail', 'get', { resource: resource.value, id: row.id })
        detail.value = result.data.record
    } finally {
        detailLoading.value = false
    }
}
async function openEditor(row?: any) {
    editingId.value = row?.id || null
    Object.keys(form).forEach((key) => delete form[key])
    editorOpen.value = true
    editorLoading.value = !!row
    try {
        if (row) {
            const result = await request('detail', 'get', { resource: resource.value, id: row.id })
            const record = result.data.record
            for (const field of definition.value.edit || []) {
                let value = record[field.key]
                if (field.key === 'cidrs' && Array.isArray(value)) value = value.join('\n')
                if (['interfaces', 'memory_soft_mib', 'memory_hard_mib', 'disk_limit_mib', 'data_dir'].includes(field.key)) {
                    value = record.settings?.[field.key]
                    if (field.key === 'interfaces' && Array.isArray(value)) value = value.join('\n')
                }
                form[field.key] = value
            }
        } else {
            form.enabled = true
            form.severity = 'medium'
            form.window_seconds = 60
            form.cooldown_seconds = 600
            if (resource.value === 'nodes')
                Object.assign(form, {
                    interfaces: 'monitor0',
                    memory_soft_mib: 2048,
                    memory_hard_mib: 4096,
                    disk_limit_mib: 2048,
                    data_dir: '/home/vm-monitor',
                })
        }
    } finally {
        editorLoading.value = false
    }
}
async function save() {
    const data = { ...form }
    if (resource.value === 'nodes') {
        data.cidrs = String(data.cidrs || '')
            .split(/[\n,]+/)
            .map((item: string) => item.trim())
            .filter(Boolean)
        data.settings = {
            interfaces: String(data.interfaces || '')
                .split(/[\n,]+/)
                .map((item: string) => item.trim())
                .filter(Boolean),
            memory_soft_mib: Number(data.memory_soft_mib),
            memory_hard_mib: Number(data.memory_hard_mib),
            disk_limit_mib: Number(data.disk_limit_mib),
            data_dir: String(data.data_dir || ''),
        }
        for (const key of ['interfaces', 'memory_soft_mib', 'memory_hard_mib', 'disk_limit_mib', 'data_dir']) delete data[key]
    }
    saving.value = true
    try {
        await request('save', 'post', { resource: resource.value, id: editingId.value || '', data })
        ElMessage.success('保存成功')
        editorOpen.value = false
        countKey = ''
        load()
    } finally {
        saving.value = false
    }
}
async function bulkSave() {
    if (!resolution.value.trim()) {
        ElMessage.warning('请填写处理记录')
        return
    }
    saving.value = true
    try {
        await request('bulkAlerts', 'post', { ids: selected.value, status: bulkStatus.value, resolution: resolution.value })
        ElMessage.success('告警已更新')
        bulkOpen.value = false
        selected.value = []
        countKey = ''
        load()
    } finally {
        saving.value = false
    }
}
async function probe(row: any) {
    actionId.value = row.id
    try {
        await request('probe', 'post', { id: row.id })
        ElMessage.success('已加入验证队列')
        load()
    } finally {
        actionId.value = null
    }
}
async function nodeConfig(row: any) {
    try {
        await ElMessageBox.confirm('生成配置会立即撤销该节点旧凭据。请及时部署新文件。', '轮换节点凭据', { type: 'warning' })
    } catch {
        return
    }
    actionId.value = row.id
    try {
        const result = await request('nodeConfig', 'post', { id: row.id })
        const blob = new Blob([JSON.stringify(result.data.config, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = 'agent.json'
        link.click()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
        ElMessage.success('已下载新配置')
    } finally {
        actionId.value = null
    }
}
async function loadScreenshot() {
    if (!detail.value?.id) return
    screenshotLoading.value = true
    try {
        const result = await request('screenshot', 'get', { id: detail.value.id })
        screenshotData.value = result.data.image
    } finally {
        screenshotLoading.value = false
    }
}
async function addManual() {
    saving.value = true
    try {
        await request('manualWebsite', 'post', { ...manual })
        ElMessage.success('网站已加入验证队列')
        manualOpen.value = false
        countKey = ''
        load()
    } finally {
        saving.value = false
    }
}
async function exportCsv() {
    exporting.value = true
    try {
        const params = new URLSearchParams({ resource: resource.value, ...filters })
        const token = useAdminInfo().getToken()
        const response = await fetch('/admin/Monitor/export?' + params.toString(), { headers: { batoken: token || '', server: 'true' } })
        if (!response.ok || !response.headers.get('content-type')?.includes('text/csv')) throw new Error('导出失败，请重新登录后重试')
        const url = URL.createObjectURL(await response.blob())
        const link = document.createElement('a')
        link.href = url
        link.download = resource.value + '.csv'
        link.click()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '导出失败')
    } finally {
        exporting.value = false
    }
}
</script>

<style scoped>
.monitor-page {
    padding: 18px;
}
.monitor-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 18px;
}
.monitor-heading h2 {
    font-size: 24px;
    margin: 0 0 6px;
}
.monitor-heading p {
    margin: 0;
    color: var(--el-text-color-secondary);
}
.monitor-heading-actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}
.monitor-card {
    border-radius: 14px;
}
.monitor-filters {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 16px;
}
.monitor-filters > * {
    width: 170px;
}
.monitor-filters .el-button {
    width: auto;
}
.monitor-column-control {
    display: flex;
    justify-content: flex-end;
    margin-bottom: 10px;
}
.monitor-column-list {
    display: flex;
    flex-direction: column;
}
.monitor-pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 16px;
    color: var(--el-text-color-secondary);
}
.monitor-evidence {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-size: 13px;
    line-height: 1.5;
}
.monitor-screenshot img {
    display: block;
    max-width: 100%;
    margin-top: 12px;
    border: 1px solid var(--el-border-color);
}
@media (max-width: 640px) {
    .monitor-page {
        padding: 10px;
    }
    .monitor-filters > * {
        width: 100%;
    }
}
</style>
