<template>
  <div class="audit">
    <h2>智能合约安全审计</h2>
    <div class="upload-section">
      <textarea v-model="contractCode" class="code-editor" placeholder="// 粘贴 Solidity 合约代码..."></textarea>
      <div class="toolbar">
        <input v-model="filename" placeholder="文件名.sol" class="filename-input" />
        <button @click="runAudit" class="btn-primary" :disabled="!contractCode">
          {{ isAuditing ? "审计中..." : "开始审计" }}
        </button>
      </div>
    </div>
    <div v-if="errorMsg" class="error-banner">{{ errorMsg }}</div>
    <div v-if="result" class="result-section">
      <template v-if="result.status === 'success'">
        <div class="score-card" :class="scoreClass">
          <div class="score-label">安全评分</div>
          <div class="score-value">{{ result.score }}</div>
          <div class="score-grade">{{ scoreGrade }}</div>
        </div>
        <div class="result-meta">审计时间：{{ formatTime(result.timestamp) }}（结果已保存，可在“审计历史”中随时查看）</div>
        <div class="vulnerabilities">
          <h3>发现漏洞 ({{ result.vulnerabilities.length }})</h3>
          <div v-for="v in result.vulnerabilities" :key="v.line + v.type" class="vuln-card" :class="v.severity">
            <div class="vuln-header">
              <span class="vuln-type">{{ v.type }}</span>
              <span class="vuln-severity">{{ v.severity }} · 第 {{ v.line }} 行</span>
            </div>
            <div class="vuln-desc">{{ v.description }}</div>
            <div class="vuln-suggest">建议: {{ v.suggestion }}</div>
          </div>
        </div>
        <div v-if="result.gasIssues.length > 0" class="gas-section">
          <h3>Gas优化建议</h3>
          <div v-for="g in result.gasIssues" :key="g.functionName" class="gas-card">
            <div class="gas-fn">{{ g.functionName }}</div>
            <div class="gas-info">当前: {{ g.currentGas }} → 优化后: {{ g.optimizedGas }} ({{ Math.round((1-g.optimizedGas/g.currentGas)*100) }}%节省)</div>
            <div class="gas-suggest">{{ g.suggestion }}</div>
          </div>
        </div>
      </template>
      <div v-else class="failed-card">
        <h3>审计失败</h3>
        <div class="failed-reason">{{ result.error }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from "vue"
import { useAuditStore } from "@/store"
import type { AuditRecord } from "@/types"

const store = useAuditStore()

const contractCode = ref(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}`)
const filename = ref("SimpleBank.sol")
const isAuditing = ref(false)
const result = ref<AuditRecord | null>(null)
const errorMsg = ref("")

const scoreClass = computed(() => {
  if (!result.value || result.value.score == null) return ""
  if (result.value.score >= 80) return "score-high"
  if (result.value.score >= 50) return "score-medium"
  return "score-low"
})

const scoreGrade = computed(() => {
  if (!result.value || result.value.score == null) return ""
  if (result.value.score >= 90) return "Excellent"
  if (result.value.score >= 70) return "Good"
  if (result.value.score >= 50) return "Fair"
  return "Poor"
})

function formatTime(ts: string) {
  return ts ? ts.replace("T", " ").slice(0, 19) : ""
}

async function runAudit() {
  isAuditing.value = true
  errorMsg.value = ""
  result.value = null
  try {
    result.value = await store.uploadAndAudit(contractCode.value, filename.value || "contract.sol")
  } catch (err: any) {
    // 后端审计失败：展示其保留的原始失败原因
    errorMsg.value = err.message
    result.value = store.currentResult
  } finally {
    isAuditing.value = false
  }
}
</script>

<style scoped>
.audit { max-width: 1000px; }
.code-editor { width: 100%; height: 300px; font-family: "Fira Code", monospace; font-size: 0.875rem; padding: 1rem; border: 1px solid #d1d5db; border-radius: 8px; background: #1e1e1e; color: #d4d4d4; resize: vertical; }
.toolbar { display: flex; gap: 1rem; margin: 1rem 0; align-items: center; }
.filename-input { padding: 0.5rem 1rem; border: 1px solid #d1d5db; border-radius: 8px; flex: 1; }
.btn-primary { background: #8b5cf6; color: white; border: none; padding: 0.625rem 1.5rem; border-radius: 8px; cursor: pointer; white-space: nowrap; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.result-section { margin-top: 2rem; }
.result-meta { color: #6b7280; font-size: 0.875rem; margin-bottom: 1rem; }
.error-banner { background: #fee2e2; color: #991b1b; border-radius: 8px; padding: 0.75rem 1rem; margin-top: 1rem; }
.failed-card { background: white; border-radius: 12px; padding: 1.5rem; border-left: 4px solid #dc2626; }
.failed-card h3 { color: #dc2626; margin-bottom: 0.75rem; }
.failed-reason { color: #374151; font-family: monospace; white-space: pre-wrap; }
.score-card { border-radius: 16px; padding: 2rem; text-align: center; color: white; margin-bottom: 2rem; }
.score-high { background: linear-gradient(135deg, #10b981, #059669); }
.score-medium { background: linear-gradient(135deg, #f59e0b, #d97706); }
.score-low { background: linear-gradient(135deg, #ef4444, #dc2626); }
.score-label { font-size: 0.875rem; opacity: 0.9; margin-bottom: 0.5rem; }
.score-value { font-size: 4rem; font-weight: 800; }
.score-grade { font-size: 1.25rem; opacity: 0.9; }
.vulnerabilities h3, .gas-section h3 { margin-bottom: 1rem; font-size: 1.125rem; }
.vuln-card { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid; }
.vuln-card.critical { border-color: #dc2626; }
.vuln-card.high { border-color: #f59e0b; }
.vuln-card.medium { border-color: #3b82f6; }
.vuln-card.low { border-color: #6b7280; }
.vuln-header { display: flex; justify-content: space-between; margin-bottom: 0.75rem; }
.vuln-type { font-weight: 600; }
.vuln-severity { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; background: #fee2e2; color: #dc2626; }
.vuln-desc { color: #374151; margin-bottom: 0.5rem; }
.vuln-suggest { font-size: 0.875rem; color: #6b7280; }
.gas-card { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
.gas-fn { font-weight: 600; color: #7c3aed; margin-bottom: 0.5rem; }
.gas-info { color: #059669; font-size: 0.875rem; margin-bottom: 0.5rem; }
.gas-suggest { font-size: 0.875rem; color: #6b7280; }
</style>