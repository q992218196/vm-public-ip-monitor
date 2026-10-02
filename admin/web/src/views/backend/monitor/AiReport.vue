<template>
    <!-- Only the output of the strict report sanitizer is inserted as HTML. -->
    <article class="ai-report" v-html="html"></article>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { renderAiReport } from './aiReport'
const props = defineProps<{ content: string }>()
const html = computed(() => renderAiReport(props.content))
</script>
<style scoped>
.ai-report {
    color: var(--el-text-color-primary);
    line-height: 1.8;
    overflow-x: auto;
    overflow-wrap: anywhere;
    padding: 12px 0;
}
.ai-report :deep(h1) {
    font-size: 24px;
    line-height: 1.4;
}
.ai-report :deep(h2) {
    font-size: 19px;
    border-bottom: 1px solid var(--el-border-color);
    padding-bottom: 8px;
    margin-top: 26px;
}
.ai-report :deep(h3) {
    font-size: 16px;
    margin-top: 20px;
}
.ai-report :deep(p) {
    margin: 12px 0;
}
.ai-report :deep(ul),
.ai-report :deep(ol) {
    padding-left: 26px;
}
.ai-report :deep(li) {
    margin: 6px 0;
}
.ai-report :deep(table) {
    border-collapse: collapse;
    min-width: 60%;
    margin: 16px 0;
    font-size: 14px;
}
.ai-report :deep(th),
.ai-report :deep(td) {
    border: 1px solid var(--el-border-color);
    padding: 10px 12px;
    text-align: left;
}
.ai-report :deep(th) {
    background: var(--el-fill-color-light);
    font-weight: 600;
}
.ai-report :deep(code) {
    background: var(--el-fill-color-light);
    border-radius: 4px;
    padding: 2px 5px;
    font-size: 0.92em;
}
.ai-report :deep(pre) {
    background: var(--el-fill-color-light);
    padding: 14px;
    border-radius: 6px;
    white-space: pre-wrap;
}
.ai-report :deep(pre code) {
    padding: 0;
}
.ai-report :deep(blockquote) {
    border-left: 3px solid var(--el-color-primary);
    margin: 14px 0;
    padding: 2px 16px;
    background: var(--el-fill-color-lighter);
}
.ai-report :deep(hr) {
    border: 0;
    border-top: 1px solid var(--el-border-color);
    margin: 24px 0;
}
</style>
