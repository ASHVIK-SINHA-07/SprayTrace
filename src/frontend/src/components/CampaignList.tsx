/** Ranked campaign cards. Tier drives the left border and badge colour. */

import type { Campaign } from '../types'

interface Props {
  campaigns: Campaign[]
  selectedId: string | null
  freshId: string | null
  onSelect: (id: string) => void
}

export function CampaignList({ campaigns, selectedId, freshId, onSelect }: Props) {
  return (
    <div className="pane-list">
      <div className="pane-head">
        <span>Campaigns</span>
        <span style={{ marginLeft: 'auto' }}>{campaigns.length}</span>
      </div>

      {campaigns.length === 0 && (
        <div className="empty">No campaigns above the escalation gate.</div>
      )}

      {campaigns.map((campaign) => {
        const classes = [
          'campaign-card',
          campaign.tier,
          campaign.campaign_id === selectedId ? 'selected' : '',
          campaign.campaign_id === freshId ? 'fresh' : '',
        ]
          .filter(Boolean)
          .join(' ')

        return (
          <button
            key={campaign.campaign_id}
            className={classes}
            onClick={() => onSelect(campaign.campaign_id)}
          >
            <div className="row1">
              <span className="cid">{campaign.campaign_id}</span>
              <span className={`badge ${campaign.tier}`}>{campaign.tier}</span>
              <span className="risk-pill">{campaign.risk.toFixed(2)}</span>
            </div>
            <div className="title">{campaign.name}</div>
            <div className="facts">
              <span>{campaign.usernames.length} accounts</span>
              <span>{campaign.event_count} events</span>
              <span>{formatSpan(campaign.span_minutes)}</span>
            </div>
          </button>
        )
      })}
    </div>
  )
}

function formatSpan(minutes: number): string {
  if (minutes < 60) return `${Math.round(minutes)} min`
  return `${(minutes / 60).toFixed(1)} h`
}
