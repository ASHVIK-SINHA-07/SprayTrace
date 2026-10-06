/** The reduction headline: raw events -> escalatable -> campaigns. */

import type { PipelineSummary } from '../types'

export function StatBar({ summary }: { summary: PipelineSummary | null }) {
  if (!summary) {
    return (
      <div className="statbar">
        <div className="stat muted">
          <div className="value">—</div>
          <div className="label">loading</div>
        </div>
      </div>
    )
  }

  const tiers = summary.by_tier

  return (
    <div className="statbar">
      <div className="stat">
        <div className="value">{summary.total_events.toLocaleString()}</div>
        <div className="label">raw events</div>
      </div>
      <div className="stat muted">
        <div className="value arrow">→</div>
        <div className="label">&nbsp;</div>
      </div>
      <div className="stat">
        <div className="value">{summary.escalated.toLocaleString()}</div>
        <div className="label">escalatable</div>
      </div>
      <div className="stat muted">
        <div className="value arrow">→</div>
        <div className="label">&nbsp;</div>
      </div>
      <div className="stat">
        <div className="value">{summary.campaigns}</div>
        <div className="label">campaigns</div>
      </div>

      <div className="stat critical">
        <div className="value">{tiers.critical}</div>
        <div className="label">critical</div>
      </div>
      <div className="stat high">
        <div className="value">{tiers.high}</div>
        <div className="label">high</div>
      </div>
      <div className="stat medium">
        <div className="value">{tiers.medium}</div>
        <div className="label">medium</div>
      </div>
      <div className="stat muted" title="Below the 0.40 gate: never escalated, retained for retrospective hunting">
        <div className="value">{summary.suppressed.toLocaleString()}</div>
        <div className="label">suppressed</div>
      </div>
    </div>
  )
}
