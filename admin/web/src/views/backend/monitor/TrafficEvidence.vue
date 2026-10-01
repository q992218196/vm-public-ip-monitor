<template>
    <section>
        <h3>{{ record.title || '连接证据' }}</h3>
        <el-alert v-if="analysis.conclusion" type="info" :closable="false" :title="analysis.conclusion" />
        <el-descriptions :column="2" border>
            <el-descriptions-item label="公网 IP">{{ record.ip || sample.ip || '—' }}</el-descriptions-item>
            <el-descriptions-item label="目标数">{{ sample.unique_targets ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="TCP 发起">{{ sample.tcp_attempts ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="SYN-ACK 回复">{{ sample.synack_replies ?? '未采集' }}</el-descriptions-item>
            <el-descriptions-item label="握手回复比例">{{ replyRatio }}</el-descriptions-item>
            <el-descriptions-item label="目标端口">{{ (sample.ports || []).join('、') || '—' }}</el-descriptions-item>
        </el-descriptions>
        <p>{{ evidence.note }}</p>
        <h4 v-if="endpoints.length">目标连接样本</h4>
        <el-table v-if="endpoints.length" :data="endpoints" border size="small">
            <el-table-column label="目标" min-width="170"
                ><template #default="scope">{{ scope.row.peer_ip }}:{{ scope.row.peer_port }}</template></el-table-column
            >
            <el-table-column prop="attempts" label="发起" width="65" />
            <el-table-column prop="synack_replies" label="回复" width="65" />
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
    </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ record: Record<string, any> }>()
const evidence = computed(() => props.record.evidence || {})
const sample = computed(() => evidence.value.sample || evidence.value)
const analysis = computed(() => evidence.value.connection_analysis || {})
const endpoints = computed<any[]>(() => sample.value.outbound_endpoints || [])
const replyRatio = computed(() => {
    const ratio = analysis.value.reply_ratio
    return typeof ratio === 'number' ? (ratio * 100).toFixed(1) + '%' : '不可计算'
})
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
