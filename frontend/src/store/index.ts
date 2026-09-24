import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { ApiResponse } from '@/types'

export interface AuditResult {
  id: string
  filename: string
  codeHash?: string
  score: number | null
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  timestamp: string
  status: 'success' | 'failed'
  error?: string
  cached?: boolean
  code?: string
}

export interface Vulnerability {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  description: string
  suggestion: string
  code?: string
}

export interface GasIssue {
  functionName: string
  currentGas: number
  optimizedGas: number
  suggestion: string
}

export interface HistoryItem {
  id: string
  filename: string
  status: 'success' | 'failed'
  score: number | null
  error: string | null
  timestamp: string
  vulnCount: number
  gasCount: number
}

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditResult[]>([])
  const currentResult = ref<AuditResult | null>(null)
  const patterns = ref<any[]>([])

  async function uploadAndAudit(code: string, filename: string) {
    const res = await axios.post<ApiResponse<AuditResult>>('/api/audit', { code, filename })
    // 失败也会返回结论体（code=1），原样交给页面展示保留下来的失败原因
    currentResult.value = res.data.data
    if (!res.data.data.cached) {
      results.value.unshift(res.data.data)
    }
    return res.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiResponse<any[]>>('/api/patterns')
    patterns.value = res.data.data
  }

  async function fetchHistory(): Promise<HistoryItem[]> {
    const res = await axios.get<ApiResponse<HistoryItem[]>>('/api/history')
    return res.data.data
  }

  async function fetchDetail(id: string): Promise<AuditResult> {
    const res = await axios.get<ApiResponse<AuditResult>>(`/api/history/${id}`)
    currentResult.value = res.data.data
    return res.data.data
  }

  return { results, currentResult, patterns, uploadAndAudit, fetchPatterns, fetchHistory, fetchDetail }
})
