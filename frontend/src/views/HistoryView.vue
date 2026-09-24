<template>
  <div class="history">
    <h2>审计历史</h2>
    <div v-if="loading" class="empty-tip">加载中...</div>
    <div v-else-if="history.length === 0" class="empty-tip">暂无审计记录</div>
    <div class="history-list">
      <div v-for="item in history" :key="item.id" class="history-card">
        <div class="history-main">
          <div class="history-row">
            <div class="history-file">{{ item.filename }}</div>
            <div v-if="item.status === 'success'" class="history-score" :class="scoreClass(item.score)">{{ item.score }}分</div>
            <div v-else class="history-status-failed">审计失败</div>
            <div class="history-time">{{ formatTime(item.timestamp) }}</div>
            <button class="btn-sm" @click="toggleDetail(item.id)">
              {{ expandedId === item.id ? "收起" : "查看详情" }}
            </button>
          </div>
          <div v-if="expandedId === item.id && detail" class="history-detail">
            <template v-if="detail.status === 'success'">
              <h4>漏洞清单（{{ detail.vulnerabilities.length }}）</h4>
              <div v-for="v in detail.vulnerabilities" :key="v.line + v.type" class="vuln-item" :class="v.severity">
                <div class="vuln-head">
                  <span class="vuln-type">{{ v.type }}</span>
                  <span class="vuln-line">{{ v.severity }} · 第 {{ v.line }} 行</span>
                </div>
                <div class="vuln-desc">{{ v.description }}</div>
                <div class="vuln-suggest">建议: {{ v.suggestion }}</div>
              </div>
              <div v-if="detail.vulnerabilities.length === 0" class="empty-tip">未发现漏洞</div>
              <template v-if="detail.gasIssues.length > 0">
                <h4>Gas优化建议</h4>
                <div v-for="g in detail.gasIssues" :key="g.functionName" class="gas-item">
                  <span class="gas-fn">{{ g.functionName }}</span>
                  <span class="gas-info">{{ g.currentGas }} → {{ g.optimizedGas }}</span>
                  <span class="gas-suggest">{{ g.suggestion }}</span>
                </div>
              </template>
            </template>
            <template v-else>
              <h4>失败原因</h4>
              <div class="failed-reason">{{ detail.error }}</div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useAuditStore } from "@/store"
import type { AuditRecord } from "@/types"

const store = useAuditStore()
const history = ref<AuditRecord[]>([])
const loading = ref(true)
const expandedId = ref<string | null>(null)
const detail = ref<AuditRecord | null>(null)

onMounted(async () => {
  try {
    history.value = await store.fetchHistory()
  } finally {
    loading.value = false
  }
})

function scoreClass(score: number | null) {
  if (score == null) return "low"
  if (score >= 70) return "high"
  if (score >= 40) return "medium"
  return "low"
}

function formatTime(ts: string) {
  return ts ? ts.replace("T", " ").slice(0, 19) : ""
}

async function toggleDetail(id: string) {
  if (expandedId.value === id) {
    expandedId.value = null
    detail.value = null
    return
  }
  expandedId.value = id
  detail.value = await store.fetchAuditDetail(id)
}
</script>

<style scoped>
.history { max-width: 800px; }
.empty-tip { color: #6b7280; padding: 1rem 0; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; }
.history-main { width: 100%; }
.history-row { display: flex; align-items: center; gap: 1rem; }
.history-file { flex: 1; font-weight: 600; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.history-status-failed { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; background: #fee2e2; color: #991b1b; }
.history-time { color: #6b7280; font-size: 0.875rem; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
.btn-sm:hover { background: #d1d5db; }
.history-detail { margin-top: 1rem; border-top: 1px solid #f3f4f6; padding-top: 1rem; }
.history-detail h4 { margin: 0.5rem 0 0.75rem; font-size: 0.95rem; }
.vuln-item { border-left: 3px solid; padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; background: #f9fafb; border-radius: 6px; }
.vuln-item.critical { border-color: #dc2626; }
.vuln-item.high { border-color: #f59e0b; }
.vuln-item.medium { border-color: #3b82f6; }
.vuln-item.low { border-color: #6b7280; }
.vuln-head { display: flex; justify-content: space-between; margin-bottom: 0.25rem; }
.vuln-type { font-weight: 600; font-size: 0.875rem; }
.vuln-line { color: #6b7280; font-size: 0.75rem; }
.vuln-desc { color: #374151; font-size: 0.875rem; margin-bottom: 0.25rem; }
.vuln-suggest { color: #6b7280; font-size: 0.8125rem; }
.gas-item { display: flex; gap: 1rem; align-items: baseline; padding: 0.375rem 0; font-size: 0.875rem; border-bottom: 1px solid #f3f4f6; }
.gas-fn { font-weight: 600; color: #7c3aed; }
.gas-info { color: #059669; }
.gas-suggest { color: #6b7280; }
.failed-reason { color: #991b1b; font-family: monospace; font-size: 0.875rem; white-space: pre-wrap; }
</style>
