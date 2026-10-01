<template>
    <section class="site-report">
        <header>
            <h3>站点监控分析</h3>
            <el-tag :type="report.review_required ? 'warning' : 'info'">{{ report.review_required ? '中风险 · 待人工复核' : '风险未确定' }}</el-tag>
        </header>
        <el-alert v-if="record.status !== 'verified'" type="warning" :closable="false" title="最近一次未验证成功；已有分析及截图可能来自历史验证。" />
        <el-descriptions :column="1" border>
            <el-descriptions-item label="公网 IP">{{ record.ip || '—' }}</el-descriptions-item>
            <el-descriptions-item label="域名／端口">{{ record.host || 'IP 直连' }} : {{ record.port }} / {{ record.scheme }}</el-descriptions-item>
            <el-descriptions-item label="站点标题">{{ record.title || '—' }}</el-descriptions-item>
            <el-descriptions-item label="网站描述">{{ record.description || '未提供' }}</el-descriptions-item>
            <el-descriptions-item label="业务类型">{{ report.business_type || record.category || '未分类' }}</el-descriptions-item>
            <el-descriptions-item label="性质">{{ report.nature || '待人工核实' }}</el-descriptions-item>
            <el-descriptions-item label="人工分类">{{ record.manual_category || '未填写' }}</el-descriptions-item>
            <el-descriptions-item label="HTTP 状态">{{ record.http_status || '—' }}</el-descriptions-item>
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
