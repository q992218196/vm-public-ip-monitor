<template>
    <div class="default-main monitor-dashboard">
        <div class="dashboard-head">
            <div>
                <h1>VM 公网流量监控</h1>
                <p>节点、网站和告警概览</p>
            </div>
            <el-button :loading="loading" @click="refresh">刷新数据</el-button>
        </div>
        <el-alert v-if="error" title="概览暂时无法加载，请检查管理服务与数据库连接。" type="error" show-icon :closable="false" />
        <el-row :gutter="16" v-loading="loading && !loaded">
            <el-col v-for="card in cards" :key="card.key" :xs="12" :sm="12" :lg="8" class="card-col">
                <router-link :to="card.path" class="metric-link">
                    <el-card shadow="hover" class="metric-card">
                        <div class="metric-label">{{ card.label }}</div>
                        <strong>{{ loaded ? Number(summary[card.key] || 0).toLocaleString() : '—' }}</strong>
                        <div class="metric-hint">{{ card.hint }}</div>
                    </el-card>
                </router-link>
            </el-col>
        </el-row>
        <el-card shadow="never" class="dashboard-note">
            <h2>查看证据</h2>
            <p>告警详情按需加载；“流量窗口”记录节点对 VM 公网 IP 的出入站统计。网站截图仅在验证任务完成后生成。</p>
            <el-space wrap>
                <router-link to="/admin/monitor/alerts"><el-button type="danger" plain>打开告警中心</el-button></router-link>
                <router-link to="/admin/monitor/websites"><el-button type="primary" plain>查看网站资产</el-button></router-link>
            </el-space>
        </el-card>
    </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import createAxios from '/@/utils/axios'

const cards = [
    { key: 'nodes', label: '活跃节点', hint: '最近 5 分钟上报', path: '/admin/monitor/nodes' },
    { key: 'ips', label: '公网 IP', hint: '已登记的 VM 地址', path: '/admin/monitor/ips' },
    { key: 'websites', label: '网站资产', hint: '包含待验证线索', path: '/admin/monitor/websites' },
    { key: 'alerts', label: '待处理告警', hint: '状态为待处理', path: '/admin/monitor/alerts' },
    { key: 'batches', label: '待分析批次', hint: '队列处理中', path: '/admin/monitor/metrics' },
]
const summary = reactive<Record<string, number>>({})
const loading = ref(false)
const loaded = ref(false)
const error = ref(false)
async function refresh() {
    loading.value = true
    error.value = false
    try {
        const response = await createAxios({ url: '/admin/Monitor/overview', method: 'get' })
        Object.assign(summary, response.data)
        loaded.value = true
    } catch {
        error.value = true
    } finally {
        loading.value = false
    }
}
onMounted(refresh)
</script>

<style scoped>
.monitor-dashboard {
    padding: 20px;
}
.dashboard-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 22px;
}
.dashboard-head h1 {
    margin: 0 0 6px;
    font-size: 26px;
}
.dashboard-head p,
.metric-hint {
    color: var(--el-text-color-secondary);
    margin: 0;
}
.card-col {
    margin-bottom: 16px;
}
.metric-link {
    text-decoration: none;
    color: inherit;
}
.metric-card {
    border-radius: 14px;
}
.metric-label {
    font-size: 14px;
    color: var(--el-text-color-secondary);
}
.metric-card strong {
    display: block;
    font-size: 32px;
    line-height: 1.5;
    margin: 8px 0;
}
.dashboard-note {
    border-radius: 14px;
    margin-top: 8px;
}
.dashboard-note h2 {
    font-size: 18px;
    margin: 0 0 8px;
}
.dashboard-note p {
    color: var(--el-text-color-secondary);
    line-height: 1.7;
}
@media (max-width: 640px) {
    .monitor-dashboard {
        padding: 10px;
    }
    .metric-card strong {
        font-size: 25px;
    }
}
</style>
