<template>
    <div class="default-main ai-settings">
        <h2>AI 分析设置</h2>
        <el-alert title="仅手动申请事件分析时调用 DeepSeek。保存配置不会发送请求。" type="info" :closable="false" />
        <el-card v-loading="loading" shadow="never">
            <el-form label-width="130px" @submit.prevent="save">
                <el-form-item label="启用手动分析"><el-switch v-model="form.enabled" /></el-form-item>
                <el-form-item label="API 地址"
                    ><el-select v-model="form.endpoint"><el-option v-for="url in endpoints" :key="url" :label="url" :value="url" /></el-select
                ></el-form-item>
                <el-form-item label="模型名称"
                    ><el-input v-model="form.model" maxlength="80" placeholder="填写 DeepSeek 账户支持的模型名称"
                /></el-form-item>
                <el-form-item label="API Key"
                    ><el-input
                        v-model="form.api_key"
                        type="password"
                        show-password
                        autocomplete="new-password"
                        :placeholder="configured ? '已配置；留空保留已有密钥' : '填写 API Key'"
                /></el-form-item>
                <el-form-item><el-button type="primary" :loading="saving" native-type="submit">保存配置</el-button></el-form-item>
            </el-form>
            <p>
                DeepSeek 文件接口支持图片，不支持 PCAP。主控先解析抓包，再发送目标 IP、端口、握手、流量和可见 HTTP 请求头摘要。API Key
                加密保存，页面不回显。
            </p>
            <p>原始 PCAP 保存在主控私有目录。HTTPS 正文和实际加密代理协议无法直接恢复；AI 报告只辅助人工判断，不会自动处罚、处理告警或加入白名单。</p>
        </el-card>
    </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import createAxios from '/@/utils/axios'
const endpoints = ['https://api.deepseek.com/chat/completions', 'https://api.deepseek.com/v1/chat/completions']
const form = reactive({ endpoint: endpoints[0], model: 'deepseek-flash', enabled: false, api_key: '' })
const loading = ref(true),
    saving = ref(false),
    configured = ref(false)
onMounted(async () => {
    try {
        const result = await createAxios({ url: '/admin/EventEvidence/settings' })
        Object.assign(form, result.data)
        configured.value = result.data.key_configured
        form.api_key = ''
    } finally {
        loading.value = false
    }
})
async function save() {
    saving.value = true
    try {
        await createAxios({ url: '/admin/EventEvidence/saveSettings', method: 'post', data: form })
        configured.value ||= !!form.api_key
        form.api_key = ''
        ElMessage.success('已保存，未调用 AI')
    } finally {
        saving.value = false
    }
}
</script>
<style scoped>
.ai-settings {
    max-width: 950px;
}
.ai-settings .el-card {
    margin-top: 18px;
}
.ai-settings .el-select {
    width: 100%;
}
.ai-settings p {
    line-height: 1.8;
    color: var(--el-text-color-secondary);
}
</style>
