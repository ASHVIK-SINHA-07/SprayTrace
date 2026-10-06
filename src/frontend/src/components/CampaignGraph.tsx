/** Attacker -> victim graph for one campaign.
 *
 * The shape is the diagnosis: one hub with a wide fan is a spray, a single
 * thick edge is brute force, many hubs sharing victims is a distributed
 * campaign. An analyst reads that faster than any table.
 */

import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import type { Core, ElementDefinition } from 'cytoscape'
import type { CampaignDetail } from '../types'

const TIER_COLOUR: Record<string, string> = {
  critical: '#f2545b',
  high: '#f0a132',
  medium: '#4a9eff',
  low: '#64748b',
}

export function CampaignGraph({ detail }: { detail: CampaignDetail }) {
  const container = useRef<HTMLDivElement>(null)
  const instance = useRef<Core | null>(null)

  useEffect(() => {
    if (!container.current) return

    const attackerColour = TIER_COLOUR[detail.tier] ?? TIER_COLOUR.low
    const elements = buildElements(detail, attackerColour)

    const cy = cytoscape({
      container: container.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            color: '#93a3bd',
            'font-size': '9px',
            'font-family': 'ui-monospace, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'background-color': 'data(colour)',
            width: 'data(size)',
            height: 'data(size)',
            'border-width': 1,
            'border-color': '#0a0e16',
          },
        },
        {
          selector: 'node[kind="source"]',
          style: {
            shape: 'round-diamond',
            color: '#e8eefb',
            'font-size': '10px',
            'font-weight': 'bold' as unknown as number,
          },
        },
        {
          // A compromised account is the thing an analyst acts on first.
          selector: 'node[compromised = 1]',
          style: {
            'border-width': 2,
            'border-color': '#f2545b',
            shape: 'star',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 'data(weight)',
            'line-color': 'data(colour)',
            'curve-style': 'haystack',
            opacity: 0.45,
          },
        },
        {
          selector: 'edge[success = 1]',
          style: { 'line-color': '#f2545b', opacity: 0.95, 'curve-style': 'bezier' },
        },
      ],
      layout: {
        name: 'concentric',
        // Sources on an inner ring, victims on an outer one. A single source
        // sits alone at the centre and the fan reads as a star; a pool spreads
        // across the inner ring, so the two attack shapes stay distinguishable
        // at a glance rather than collapsing into one blob.
        concentric: (node) => (node.data('kind') === 'source' ? 10 : 1),
        levelWidth: () => 1,
        minNodeSpacing: detail.source_ips.length > 6 ? 26 : 14,
        spacingFactor: detail.source_ips.length > 6 ? 1.35 : 1,
        padding: 22,
        animate: false,
      },
      minZoom: 0.3,
      maxZoom: 2.5,
      wheelSensitivity: 0.2,
    })

    instance.current = cy
    return () => {
      cy.destroy()
      instance.current = null
    }
  }, [detail])

  const victims = detail.usernames.length
  const compromised = detail.events.filter((e) => e.success).length

  return (
    <div>
      <div className="graph-legend">
        <span><i className="dot source" /> {detail.source_ips.length} source{detail.source_ips.length === 1 ? '' : 's'}</span>
        <span><i className="dot victim" /> {victims} accounts</span>
        {compromised > 0 && (
          <span className="warn"><i className="dot breach" /> {compromised} succeeded</span>
        )}
      </div>
      <div ref={container} className="graph-canvas" />
      {victims > 18 && (
        <div className="graph-note">
          Account labels hidden above 18 victims — hover a node, or read the
          event table below.
        </div>
      )}
    </div>
  )
}

function buildElements(detail: CampaignDetail, attackerColour: string): ElementDefinition[] {
  const elements: ElementDefinition[] = []

  for (const ip of detail.source_ips) {
    elements.push({
      data: {
        id: `ip:${ip}`,
        label: ip,
        kind: 'source',
        colour: attackerColour,
        // Scale the hub so a 28-address pool still reads as many small nodes
        // rather than one dominant blob.
        size: detail.source_ips.length > 6 ? 16 : 26,
      },
    })
  }

  const compromised = new Set(
    detail.events.filter((event) => event.success).map((event) => event.username),
  )

  for (const username of detail.usernames) {
    elements.push({
      data: {
        id: `user:${username}`,
        // Labels become an unreadable ring past a few dozen victims; the fan
        // itself carries the meaning, and the table below has the names.
        label: detail.usernames.length <= 18 ? username.split('@')[0] : '',
        kind: 'user',
        colour: compromised.has(username) ? '#f2545b' : '#2d3b55',
        size: compromised.has(username) ? 14 : 9,
        compromised: compromised.has(username) ? 1 : 0,
      },
    })
  }

  // One edge per (source, account) pair, weighted by attempt count.
  const seen = new Map<string, { attempts: number; success: boolean }>()
  for (const event of detail.events) {
    const key = `${event.source_ip}|${event.username}`
    const current = seen.get(key) ?? { attempts: 0, success: false }
    current.attempts += 1
    current.success = current.success || event.success
    seen.set(key, current)
  }

  for (const [key, { attempts, success }] of seen) {
    const [ip, username] = key.split('|')
    elements.push({
      data: {
        id: `e:${key}`,
        source: `ip:${ip}`,
        target: `user:${username}`,
        weight: Math.min(4, 0.8 + attempts * 0.5),
        colour: success ? '#f2545b' : '#2d3b55',
        success: success ? 1 : 0,
      },
    })
  }

  return elements
}
