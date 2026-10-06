/** Thin fetch wrapper over the SprayTrace API. Shapes live in types.ts. */

import type {
  Campaign,
  CampaignDetail,
  PipelineSummary,
  ScoredEvent,
  Tier,
} from './types'

const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE}${path}`)
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} — ${path}`)
  }
  return response.json() as Promise<T>
}

async function post<T>(path: string, body?: FormData): Promise<T> {
  const response = await fetch(`${BASE}${path}`, { method: 'POST', body })
  if (!response.ok) {
    const detail = await response.json().catch(() => null)
    throw new Error(detail?.detail ?? `${response.status} ${response.statusText}`)
  }
  return response.json() as Promise<T>
}

export interface AuditResponse {
  total: number
  note: string
  events: ScoredEvent[]
}

export interface ReplayStep {
  event_id: number
  timestamp: string
  username: string
  source_ip: string
  risk: number
  tier: Tier
  success: boolean
  campaign_id: string
}

export interface InjectResponse {
  injected_events: number
  accounts_targeted: number
  source_ip: string
  campaign: Campaign | null
  summary: PipelineSummary
}

export const api = {
  summary: () => get<PipelineSummary>('/summary'),
  campaigns: () => get<Campaign[]>('/campaigns'),
  campaign: (id: string) => get<CampaignDetail>(`/campaigns/${id}`),
  events: (params: Record<string, string> = {}) =>
    get<ScoredEvent[]>(`/events?${new URLSearchParams(params)}`),
  user: (username: string) => get<unknown>(`/users/${encodeURIComponent(username)}`),
  audit: () => get<AuditResponse>('/audit'),
  replay: () => get<{ steps: ReplayStep[]; campaigns: Campaign[] }>('/replay'),
  inject: (accounts = 45) => post<InjectResponse>(`/inject?accounts=${accounts}`),
  reset: () => post<PipelineSummary>('/reset'),
  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return post<PipelineSummary & { filename: string }>('/analyze', form)
  },
}
