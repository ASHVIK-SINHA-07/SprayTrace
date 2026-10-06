/** One campaign: why it fired, what it touched, and every event behind it. */

import { useState } from 'react'
import type { CampaignDetail as Detail } from '../types'
import { CampaignGraph } from './CampaignGraph'
import { ReplayTimeline } from './ReplayTimeline'

export function CampaignDetailPane({ detail }: { detail: Detail | null }) {
  const [reached, setReached] = useState<number | null>(null)

  if (!detail) {
    return <div className="empty">Select a campaign to see its evidence.</div>
  }

  // While scrubbing, the table follows the playhead so the graph, the timeline
  // and the evidence all describe the same moment.
  const shownEvents =
    reached === null ? detail.events : detail.events.slice(0, reached)

  const accounts = detail.usernames.length
  const perAccount = accounts ? detail.failed_count / accounts : 0

  return (
    <div className="pane-detail">
      <div className="detail-head">
        <div className="row">
          <span className="cid" style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>
            {detail.campaign_id}
          </span>
          <span className={`badge ${detail.tier}`}>{detail.tier}</span>
          <span className="technique">{detail.technique}</span>
          <span className="risk-pill">risk {detail.risk.toFixed(2)}</span>
        </div>
        <h2>{detail.name}</h2>
      </div>

      {/* The product claim is explainability, so the reason leads. */}
      <div className="evidence">
        <span className="why">Why this fired</span>
        {detail.evidence}
      </div>

      <div className="metrics">
        <div className="metric">
          <div className="v">{accounts}</div>
          <div className="k">accounts hit</div>
        </div>
        <div className="metric">
          <div className="v">{perAccount.toFixed(1)}</div>
          <div className="k">tries / account</div>
        </div>
        <div className="metric">
          <div className="v">{formatSpan(detail.span_minutes)}</div>
          <div className="k">time span</div>
        </div>
        <div className={`metric ${detail.success_count > 0 ? 'warn' : ''}`}>
          <div className="v">{detail.success_count}</div>
          <div className="k">succeeded</div>
        </div>
        <div className="metric">
          <div className="v">{detail.source_ips.length}</div>
          <div className="k">source IPs</div>
        </div>
      </div>

      <div className="section-title">Attack graph</div>
      <CampaignGraph detail={detail} />

      <div className="section-title">Replay</div>
      <ReplayTimeline detail={detail} onCursorChange={setReached} />

      <div className="section-title">Sources</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
        {detail.source_ips.join(' · ')}
      </div>

      <div className="section-title">
        Events ({shownEvents.length}
        {reached !== null && reached < detail.events.length
          ? ` of ${detail.events.length}`
          : ''}
        )
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Account</th>
              <th>Source</th>
              <th>Location</th>
              <th>Result</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {shownEvents.map((event) => (
              <tr key={event.event_id}>
                <td>{event.timestamp.replace('T', ' ').replace('Z', '')}</td>
                <td>{event.username}</td>
                <td>{event.source_ip}</td>
                <td>
                  {event.city}, {event.country}
                </td>
                <td className={event.success ? 'ok' : 'fail'}>
                  {event.success ? 'success' : 'failed'}
                </td>
                <td>{event.risk.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function formatSpan(minutes: number): string {
  if (minutes < 60) return `${Math.round(minutes)}m`
  return `${(minutes / 60).toFixed(1)}h`
}
