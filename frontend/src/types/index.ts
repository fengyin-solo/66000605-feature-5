export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
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

export interface AuditRecord {
  id: string
  filename: string
  codeHash: string
  status: 'success' | 'failed'
  score: number | null
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  error: string | null
  timestamp: string
}
