<template>
  <div class="history">
    <h2>审计历史</h2>

    <div v-if="loading" class="state-hint">加载中...</div>
    <div v-else-if="historyItems.length === 0" class="state-hint">暂无审计记录</div>

    <div v-else class="history-list">
      <div v-for="item in historyItems" :key="item.id" class="history-block">
        <div class="history-card">
          <div class="history-file">{{ item.filename }}</div>
          <div v-if="item.status === 'failed'" class="history-badge fail">失败</div>
          <div v-else class="history-score" :class="item.score !== null && item.score >= 70 ? 'high' : item.score !== null && item.score >= 40 ? 'medium' : 'low'">{{ item.score }}分</div>
          <div class="history-meta">
            <div class="history-time">{{ item.timestamp }}</div>
            <div v-if="item.status === 'success'" class="history-counts">漏洞 {{ item.vulnCount }} · Gas {{ item.gasCount }}</div>
          </div>
          <button class="btn-sm" @click="toggleDetail(item.id)">{{ detailId === item.id ? '收起详情' : '查看详情' }}</button>
        </div>

        <div v-if="detailId === item.id" class="detail-panel">
          <div v-if="detailLoading" class="state-hint">详情加载中...</div>
          <template v-else-if="detail">
            <div v-if="detail.status === 'failed'" class="fail-reason">{{ detail.error }}</div>
            <template v-else>
              <div class="detail-score">安全评分：{{ detail.score }}</div>
              <div v-for="(v, i) in detail.vulnerabilities" :key="v.line + v.type + i" class="detail-vuln" :class="v.severity">
                <div class="detail-vuln-head">{{ v.type }} <span class="muted">· 第 {{ v.line }} 行 · {{ v.severity }}</span></div>
                <div>{{ v.description }}</div>
                <div class="muted">建议：{{ v.suggestion }}</div>
              </div>
              <div v-if="detail.vulnerabilities.length === 0" class="muted">未发现匹配的漏洞模式。</div>
            </template>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useAuditStore, type HistoryItem, type AuditResult } from "@/store"

const store = useAuditStore()
const historyItems = ref<HistoryItem[]>([])
const loading = ref(true)
const detailId = ref<string | null>(null)
const detail = ref<AuditResult | null>(null)
const detailLoading = ref(false)

onMounted(loadHistory)

async function loadHistory() {
  loading.value = true
  try {
    historyItems.value = await store.fetchHistory()
  } finally {
    loading.value = false
  }
}

async function toggleDetail(id: string) {
  if (detailId.value === id) {
    detailId.value = null
    detail.value = null
    return
  }
  detailId.value = id
  detail.value = null
  detailLoading.value = true
  try {
    detail.value = await store.fetchDetail(id)
  } finally {
    detailLoading.value = false
  }
}
</script>

<style scoped>
.history { max-width: 800px; }
.state-hint { color: #6b7280; padding: 2rem 0; text-align: center; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; display: flex; align-items: center; gap: 1rem; }
.history-file { flex: 1; font-weight: 600; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.history-badge.fail { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.75rem; background: #fee2e2; color: #991b1b; }
.history-meta { text-align: right; }
.history-time { color: #6b7280; font-size: 0.875rem; }
.history-counts { color: #9ca3af; font-size: 0.75rem; margin-top: 0.125rem; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
.detail-panel { background: white; border-radius: 0 0 12px 12px; margin-top: -0.5rem; padding: 1rem 1.25rem 1.25rem; border-top: 1px solid #f3f4f6; }
.detail-score { font-weight: 700; margin-bottom: 0.75rem; }
.detail-vuln { border-left: 3px solid #d1d5db; padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; background: #fafafa; border-radius: 0 6px 6px 0; font-size: 0.875rem; }
.detail-vuln.critical { border-color: #dc2626; }
.detail-vuln.high { border-color: #f59e0b; }
.detail-vuln.medium { border-color: #3b82f6; }
.detail-vuln-head { font-weight: 600; margin-bottom: 0.25rem; }
.fail-reason { font-family: monospace; color: #991b1b; background: #fef2f2; border-radius: 6px; padding: 0.75rem; white-space: pre-wrap; word-break: break-all; }
.muted { color: #6b7280; }
</style>
