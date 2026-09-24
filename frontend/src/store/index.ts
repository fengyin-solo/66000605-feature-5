import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import type { ApiResponse, AuditRecord } from '@/types'

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditRecord[]>([])
  const currentResult = ref<AuditRecord | null>(null)
  const patterns = ref<any[]>([])

  async function uploadAndAudit(code: string, filename: string): Promise<AuditRecord> {
    try {
      const res = await axios.post<ApiResponse<AuditRecord>>('/api/audit', { code, filename })
      currentResult.value = res.data.data
      return res.data.data
    } catch (err: any) {
      // 保留后端返回的原始失败原因
      const data = err?.response?.data
      if (data?.data) currentResult.value = data.data
      throw new Error(data?.message || err.message || '审计请求失败')
    }
  }

  async function fetchHistory(): Promise<AuditRecord[]> {
    const res = await axios.get<ApiResponse<AuditRecord[]>>('/api/history')
    results.value = res.data.data
    return res.data.data
  }

  async function fetchAuditDetail(id: string): Promise<AuditRecord> {
    const res = await axios.get<ApiResponse<AuditRecord>>(`/api/audit/${id}`)
    return res.data.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiResponse<any[]>>('/api/patterns')
    patterns.value = res.data.data
  }

  return { results, currentResult, patterns, uploadAndAudit, fetchHistory, fetchAuditDetail, fetchPatterns }
})
