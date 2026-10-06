/** Shapes returned by the SprayTrace API. Mirrors docs/api_spec.md. */

export type Tier = 'critical' | 'high' | 'medium' | 'low'

export type AttackTechnique = 'T1110.001' | 'T1110.003' | 'T1078'

export type DetectorName =
  | 'brute_force'
  | 'password_spray'
  | 'impossible_travel'
  | 'isolation_forest'

export interface AuthEvent {
  event_id: number
  timestamp: string
  username: string
  source_ip: string
  country: string
  city: string
  latitude: number
  longitude: number
  success: boolean
  device_id: string
  user_agent: string
}

export interface Alert {
  event_id: number
  detector: DetectorName
  score: number
  attack_technique: AttackTechnique | null
  evidence: string
}

export interface ScoredEvent extends AuthEvent {
  risk: number
  tier: Tier
  detectors: DetectorName[]
}

export interface Campaign {
  campaign_id: string
  name: string
  technique: AttackTechnique
  risk: number
  tier: Tier
  first_seen: string
  last_seen: string
  span_minutes: number
  source_ips: string[]
  usernames: string[]
  event_count: number
  failed_count: number
  success_count: number
  evidence: string
}

export interface CampaignDetail extends Campaign {
  events: ScoredEvent[]
  alerts: Alert[]
}

export interface PipelineSummary {
  total_events: number
  alerts: number
  campaigns: number
  suppressed: number
  by_tier: Record<Tier, number>
}

export interface Metrics {
  calibrated: boolean
  configurations: EvalRow[]
  noise_reduction_pct: number | null
}

export interface EvalRow {
  name: string
  precision: number | null
  recall: number | null
  f1: number | null
  alert_to_tp: number | null
  noise_reduction: number | null
}
