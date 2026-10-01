<template>
    <div class="default-main monitor-page">
        <div class="monitor-heading">
            <div>
                <h2>{{ definition.title }}</h2>
                <p>监控数据按需读取，证据在打开单条详情时加载；时间按浏览器本地时区显示。</p>
            </div>
            <div class="monitor-heading-actions">
                <el-button v-if="canCreate" type="primary" @click="openEditor()">新增</el-button>
                <el-button v-if="resource === 'websites' && isAdmin" @click="manualOpen = true">添加已知网站</el-button>
                <el-button v-if="resource === 'alerts' && selected.length && isAdmin" type="primary" @click="bulkOpen = true"
                    >处理所选 {{ selected.length }} 条</el-button
                >
                <el-button
                    v-if="resource === 'nodes' && selectedNodes.length && isAdmin"
                    type="primary"
                    :loading="updatingAgent"
                    @click="requestAgentUpdate(selectedNodes)"
                    >下发更新到所选 {{ selectedNodes.length }} 个节点</el-button
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
                @sort-change="onSortChange"
                @selection-change="onSelectionChange"
            >
                <el-table-column v-if="(resource === 'alerts' || resource === 'nodes') && isAdmin" type="selection" width="48" />
                <el-table-column
                    v-for="column in visibleColumns"
                    :key="column.key"
                    :prop="column.key"
                    :label="column.label"
                    :sortable="resource === 'alerts' && alertSortKeys.includes(column.key) ? 'custom' : false"
                    min-width="130"
                    show-overflow-tooltip
                >
                    <template #default="scope">
                        <el-tag
                            v-if="column.key === 'status' || column.key === 'severity'"
                            :type="tagType(scope.row[column.key])"
                            :class="resource === 'alerts' ? 'monitor-clickable' : ''"
                            @click="filterAlert(column.key, scope.row)"
                            >{{ display(scope.row[column.key]) }}</el-tag
                        >
                        <el-tag
                            v-else-if="column.key === 'agent_update_status'"
                            :type="agentUpdateTag(scope.row)"
                            :title="scope.row.agent_update_error || ''"
                            >{{ agentUpdateStatus(scope.row) }}</el-tag
                        >
                        <a
                            v-else-if="column.key === 'host' && resource === 'websites' && scope.row.host"
                            :href="websiteUrl(scope.row)"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="monitor-host-link"
                            >{{ scope.row.host }}</a
                        >
                        <button
                            v-else-if="resource === 'alerts' && (column.key === 'ip' || column.key === 'title')"
                            type="button"
                            class="monitor-filter-link"
                            @click="filterAlert(column.key, scope.row)"
                        >
                            {{ display(scope.row[column.key]) }}
                        </button>
                        <span v-else>{{ isTimeColumn(column.key) ? displayUtcTime(scope.row[column.key]) : display(scope.row[column.key]) }}</span>
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
                        <el-button v-if="isAdmin && resource === 'nodes'" link type="primary" @click="openAgentCommand(scope.row)"
                            >生成安装命令</el-button
                        >
                        <el-button v-if="isAdmin && resource === 'nodes'" link type="warning" @click="openUninstallCommand(scope.row)">
                            卸载命令</el-button
                        >
                        <el-button
                            v-if="isAdmin && resource === 'nodes'"
                            link
                            type="primary"
                            :loading="updatingAgent && actionId === scope.row.id"
                            @click="requestAgentUpdate([scope.row.id])"
                            >更新 Agent</el-button
                        >
                        <el-button
                            v-if="isAdmin && resource === 'alerts'"
                            link
                            type="warning"
                            :loading="actionId === scope.row.id"
                            @click="whitelistAlert(scope.row)"
                            >加入白名单</el-button
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
            <el-result v-else-if="detailError" icon="warning" title="证据暂时无法加载" :sub-title="detailError">
                <template #extra><el-button type="primary" @click="retryDetail">重试</el-button></template>
            </el-result>
            <template v-else>
                <el-button
                    v-if="resource === 'alerts' && detail && isAdmin"
                    type="warning"
                    :loading="actionId === detail.id"
                    @click="whitelistAlert(detail)"
                    >加入白名单</el-button
                >
                <SiteReport v-if="resource === 'websites' && detail" :record="detail" />
                <TrafficEvidence
                    v-if="detail && ((resource === 'alerts' && detail.evidence?.sample) || (resource === 'metrics' && detail.evidence))"
                    :record="detail"
                />
                <el-descriptions v-if="['alerts', 'protocols'].includes(resource) && detail?.evidence?.candidate_protocols" :column="1" border>
                    <el-descriptions-item label="疑似代理协议候选">{{ detail.evidence.candidate_protocols.join('、') }}</el-descriptions-item>
                    <el-descriptions-item label="本机端口">{{ detail.evidence.local_port }}</el-descriptions-item>
                    <el-descriptions-item label="传输外观">{{ detail.evidence.transport }}</el-descriptions-item>
                    <el-descriptions-item label="双向对端数">{{ detail.evidence.peer_count }}</el-descriptions-item>
                    <el-descriptions-item label="同窗口出站目标数">{{ detail.evidence.egress_target_count }}</el-descriptions-item>
                    <el-descriptions-item label="观察方法">{{ detail.evidence.method }}</el-descriptions-item>
                    <el-descriptions-item label="结论限制">{{ detail.evidence.note }}</el-descriptions-item>
                </el-descriptions>
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
                <el-alert
                    v-if="resource === 'alerts' && detail?.kind === 'horizontal_scan'"
                    type="info"
                    :closable="false"
                    title="这是多目标连接行为线索，不等于违规或已确认扫描。请结合目标端口、握手响应、业务用途和历史基线复核。"
                />
                <p class="monitor-time-note">时间按浏览器本地时区显示；下方原始证据中的数据库时间为 UTC。</p>
                <el-collapse v-if="['websites', 'alerts', 'metrics', 'protocols'].includes(resource)">
                    <el-collapse-item title="查看原始记录与证据" name="raw">
                        <pre class="monitor-evidence">{{ JSON.stringify(detail, null, 2) }}</pre>
                    </el-collapse-item>
                </el-collapse>
                <pre v-else class="monitor-evidence">{{ JSON.stringify(detail, null, 2) }}</pre>
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
        <el-dialog v-model="uninstallCommandOpen" :title="'卸载 Agent · ' + agentCommandNode" width="min(760px, 94vw)">
            <el-alert
                title="在目标宿主机以 root 执行。仅停止并移除 Agent 服务；保留配置、程序、缓存、日志和网络配置。不轮换节点凭据，后台节点记录也会保留。"
                type="warning"
                :closable="false"
            />
            <pre class="monitor-command">{{ uninstallCommand }}</pre>
            <template #footer>
                <el-button @click="uninstallCommandOpen = false">关闭</el-button>
                <el-button type="primary" @click="copyCommand(uninstallCommand)">复制卸载命令</el-button>
            </template>
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
        <el-dialog v-model="agentCommandOpen" :title="'安装 Agent · ' + agentCommandNode" width="min(760px, 94vw)">
            <el-alert
                title="命令下载配置、Agent、安装和卸载脚本并设置权限。重复安装会备份并替换程序和配置、重启服务；相同数据目录内的缓存与日志保留。配置链接只能使用一次，10 分钟后过期；旧令牌已撤销，请勿公开命令。"
                type="warning"
                :closable="false"
            />
            <pre class="monitor-command">{{ agentCommand }}</pre>
            <template #footer
                ><el-button @click="agentCommandOpen = false">关闭</el-button
                ><el-button type="primary" @click="copyAgentCommand">复制命令</el-button></template
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
import SiteReport from './SiteReport.vue'
import TrafficEvidence from './TrafficEvidence.vue'

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
            col('agent_version', '当前版本'),
            col('agent_update_status', '更新状态'),
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
        columns: [
            col('cidr', '源公网 IP/CIDR'),
            col('kind', '告警类型'),
            col('reason', '原因'),
            col('node_id', '适用节点'),
            col('expires_at', '失效时间'),
        ],
        edit: [
            col('cidr', '源公网 IP/CIDR'),
            {
                ...col('kind', '仅抑制此类型（留空为全部）'),
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
                    node_offline: '节点上报中断（CIDR 留空）',
                    capture_degraded: '采集覆盖下降（CIDR 留空）',
                }),
            },
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
        status: options({ pending: '等待', leased: '执行中', complete: '完成', failed: '失败' }),
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
const alertSortKeys = ['title', 'ip', 'severity', 'status', 'occurrences', 'last_seen_at']
const sortField = ref('last_seen_at')
const sortDirection = ref('desc')
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
const selectedNodes = ref<string[]>([])
const updatingAgent = ref(false)
const agentReleaseVersion = ref('')
const filters = reactive({ search: '', ip: '', node: '', status: '', severity: '', review: '' })
const detail = ref<any>(null)
const detailOpen = ref(false)
const detailLoading = ref(false)
const detailError = ref('')
const detailId = ref<number | string | null>(null)
let detailSequence = 0
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
const agentCommandOpen = ref(false)
const agentCommandNode = ref('')
const agentCommand = ref('')
const uninstallCommandOpen = ref(false)
const uninstallCommand = ref('')
const visibleKeys = ref<string[]>([])
const visibleColumns = computed(() => definition.value.columns.filter((column) => visibleKeys.value.includes(column.key)))
const canCreate = computed(() => isAdmin.value && definition.value.create)

function request(action: string, method: 'get' | 'post', data: Record<string, any> = {}, timeout?: number) {
    return createAxios({ url: '/admin/Monitor/' + action, method, timeout, ...(method === 'get' ? { params: data } : { data }) })
}
function onSelectionChange(items: any[]) {
    if (resource.value === 'alerts') selected.value = items.map((item) => Number(item.id))
    if (resource.value === 'nodes') selectedNodes.value = items.map((item) => String(item.id))
}
function agentUpdateStatus(row: any): string {
    if (!row.agent_desired_version) return '未下发'
    if (row.agent_version === row.agent_desired_version) return '已更新'
    if (row.agent_update_error) return '失败：' + String(row.agent_update_error).slice(0, 80)
    if (!row.agent_version || /^0\.[0-3]\./.test(String(row.agent_version))) return '需先手动安装新版'
    return '等待节点领取 ' + row.agent_desired_version
}
function agentUpdateTag(row: any): 'success' | 'warning' | 'danger' | 'info' {
    if (!row.agent_desired_version) return 'info'
    if (row.agent_version === row.agent_desired_version) return 'success'
    return row.agent_update_error ? 'danger' : 'warning'
}
async function loadAgentRelease() {
    try {
        const result = await request('agentRelease', 'get')
        agentReleaseVersion.value = String(result.data.release.version)
    } catch {
        agentReleaseVersion.value = ''
    }
}
function onSortChange({ prop, order }: { prop: string; order: string | null }) {
    if (resource.value !== 'alerts') return
    sortField.value = alertSortKeys.includes(prop) && order ? prop : 'last_seen_at'
    sortDirection.value = order === 'ascending' ? 'asc' : 'desc'
    page.value = 1
    load()
}
function filterAlert(key: string, row: any) {
    if (resource.value !== 'alerts') return
    if (key === 'title') filters.search = String(row.title || '')
    if (key === 'ip') filters.ip = String(row.ip || '')
    if (key === 'severity') filters.severity = String(row.severity || '')
    if (key === 'status') filters.status = String(row.status || '')
    resetAndLoad()
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
        const result = await request('index', 'get', {
            ...query,
            page: page.value,
            limit: limit.value,
            sort: sortField.value,
            direction: sortDirection.value,
        })
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
        sortField.value = 'last_seen_at'
        sortDirection.value = 'desc'
        countKey = ''
        selected.value = []
        selectedNodes.value = []
        visibleKeys.value = definition.value.columns.filter((column) => column.key !== 'description').map((column) => column.key)
        Object.assign(filters, { search: '', ip: '', node: '', status: '', severity: '', review: '' })
        load()
        if (resource.value === 'nodes') void loadAgentRelease()
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
        complete: '完成',
        high: '高',
        medium: '中',
        low: '低',
    }
    if (labels[String(value)]) return labels[String(value)]
    return String(value)
}
const timeColumns = ['last_seen_at', 'first_seen_at', 'last_probed_at', 'window_start', 'window_end', 'created_at', 'updated_at', 'expires_at']
function isTimeColumn(key: string): boolean {
    return timeColumns.includes(key)
}
function displayUtcTime(value: any): string {
    if (!value) return '—'
    const raw = String(value).replace(' ', 'T')
    const date = new Date(/(Z|[+-]\d{2}:\d{2})$/.test(raw) ? raw : raw + 'Z')
    if (Number.isNaN(date.getTime())) return String(value)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}
function websiteUrl(row: any): string {
    const host = String(row.host || row.ip || '')
    const authority = host.includes(':') ? '[' + host + ']' : host
    return String(row.scheme || 'http') + '://' + authority + ':' + Number(row.port) + '/'
}
function tagType(value: string) {
    if (['open', 'failed', 'high'].includes(value)) return 'danger'
    if (['acknowledged', 'candidate', 'medium', 'pending'].includes(value)) return 'warning'
    if (['resolved', 'verified', 'complete', 'low'].includes(value)) return 'success'
    return 'info'
}
async function openDetail(row: any) {
    detailId.value = row.id
    detailOpen.value = true
    await fetchDetail()
}
function retryDetail() {
    void fetchDetail()
}
async function fetchDetail() {
    if (detailId.value === null) return
    const sequence = ++detailSequence
    detailLoading.value = true
    detailError.value = ''
    detail.value = null
    screenshotData.value = ''
    try {
        const result = await request('detail', 'get', { resource: resource.value, id: detailId.value }, 30000)
        if (sequence === detailSequence) detail.value = result.data.record
    } catch (error: any) {
        if (sequence === detailSequence)
            detailError.value = error?.message?.includes('timeout')
                ? '请求超时，请重试；若持续出现，请检查管理服务与数据库负载。'
                : String(error?.msg || error?.message || '请求失败')
    } finally {
        if (sequence === detailSequence) detailLoading.value = false
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
                if (field.key === 'expires_at' && value) value = displayUtcTime(value)
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
    if (resource.value === 'exclusions' && data.expires_at) {
        const local = new Date(String(data.expires_at).replace(' ', 'T'))
        if (!Number.isNaN(local.getTime())) data.expires_at = local.toISOString().slice(0, 19).replace('T', ' ')
    }
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
async function whitelistAlert(row: any) {
    try {
        await ElMessageBox.confirm(
            `暂停节点“${row.node_name || row.node_id}”${row.ip ? '上公网 IP ' + row.ip : ''}的“${row.title}”类型告警 30 天，并处理同范围待处理告警。采集继续运行。`,
            '加入白名单',
            { type: 'warning', confirmButtonText: '确认加入' }
        )
    } catch {
        return
    }
    actionId.value = row.id
    try {
        const result = await request('whitelistAlert', 'post', { id: row.id })
        ElMessage.success(result.msg || '白名单已生效')
        countKey = ''
        await load()
        if (detailOpen.value && detailId.value === row.id) await fetchDetail()
    } finally {
        actionId.value = null
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
async function openAgentCommand(row: any) {
    try {
        await ElMessageBox.confirm('生成命令会立即撤销该节点旧凭据。请在 10 分钟内到目标宿主机执行。', '生成一次性安装命令', { type: 'warning' })
    } catch {
        return
    }
    actionId.value = row.id
    try {
        const result = await request('nodeBootstrap', 'post', { id: row.id })
        const origin = window.location.origin
        const ticket = String(result.data.ticket)
        agentCommand.value = `set -e\numask 077\nmkdir -p /home/vm-monitor-install\ncd /home/vm-monitor-install\ncurl --proto '=https' --tlsv1.2 -H 'server: true' -fsSLo agent.json '${origin}/api/AgentBootstrap/config?ticket=${ticket}'\nchmod 600 agent.json\ncurl --proto '=https' --tlsv1.2 -fsSLo vm-agent-linux-amd64 '${origin}/downloads/vm-agent-linux-amd64'\ncurl --proto '=https' --tlsv1.2 -fsSLo install.sh '${origin}/downloads/install.sh'\ncurl --proto '=https' --tlsv1.2 -fsSLo uninstall.sh '${origin}/downloads/uninstall.sh'\ncurl --proto '=https' --tlsv1.2 -fsSLo SHA256SUMS '${origin}/downloads/SHA256SUMS'\nsha256sum -c SHA256SUMS\nchmod 700 vm-agent-linux-amd64 install.sh uninstall.sh\nbash install.sh ./agent.json ./vm-agent-linux-amd64`
        agentCommandNode.value = String(row.name || row.id)
        agentCommandOpen.value = true
    } finally {
        actionId.value = null
    }
}
async function requestAgentUpdate(ids: string[]) {
    const version = agentReleaseVersion.value || '主控已发布版本'
    try {
        await ElMessageBox.confirm(`向 ${ids.length} 个节点下发 ${version} 更新？节点会在下一次轮询后自行校验并重启。`, '下发 Agent 更新', {
            type: 'warning',
        })
    } catch {
        return
    }
    updatingAgent.value = true
    actionId.value = ids.length === 1 ? ids[0] : null
    try {
        const result = await request('agentUpdate', 'post', { ids })
        ElMessage.success(result.msg || '已下发更新')
        selectedNodes.value = []
        await load()
    } finally {
        updatingAgent.value = false
        actionId.value = null
    }
}
async function copyAgentCommand() {
    await copyCommand(agentCommand.value)
}
function openUninstallCommand(row: any) {
    const origin = window.location.origin
    agentCommandNode.value = String(row.name || row.id)
    uninstallCommand.value = `set -e\numask 077\nmkdir -p /home/vm-monitor-install\ncd /home/vm-monitor-install\ncurl --proto '=https' --tlsv1.2 -fsSLo uninstall.sh '${origin}/downloads/uninstall.sh'\ncurl --proto '=https' --tlsv1.2 -fsSLo SHA256SUMS '${origin}/downloads/SHA256SUMS'\nawk '$2 == "uninstall.sh" {print; found=1} END {if (!found) exit 1}' SHA256SUMS > uninstall.sha256\nsha256sum -c uninstall.sha256\nchmod 700 uninstall.sh\nbash ./uninstall.sh`
    uninstallCommandOpen.value = true
}
async function copyCommand(command: string) {
    try {
        await navigator.clipboard.writeText(command)
        ElMessage.success('命令已复制')
    } catch {
        ElMessage.error('复制失败，请手动复制文本')
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
.monitor-host-link {
    text-decoration: none;
}
.monitor-host-link:hover {
    text-decoration: none;
}
.monitor-filter-link {
    padding: 0;
    border: 0;
    color: var(--el-color-primary);
    background: transparent;
    cursor: pointer;
    font: inherit;
    text-align: left;
}
.monitor-filter-link:hover {
    color: var(--el-color-primary-light-3);
}
.monitor-clickable {
    cursor: pointer;
}
.monitor-time-note {
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.monitor-command {
    margin-top: 14px;
    padding: 14px;
    border-radius: 8px;
    background: var(--el-fill-color-light);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-size: 12px;
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
