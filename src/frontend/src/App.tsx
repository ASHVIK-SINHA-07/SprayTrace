/** SprayTrace dashboard shell. */

import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api'
import { CampaignDetailPane } from './components/CampaignDetail'
import { CampaignList } from './components/CampaignList'
import { StatBar } from './components/StatBar'
import type { Campaign, CampaignDetail, PipelineSummary } from './types'

export default function App() {
  const [summary, setSummary] = useState<PipelineSummary | null>(null)
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  // Deep-link the selection so a campaign can be shared or reopened, and so
  // a demo can jump straight to the one being discussed.
  const [selectedId, setSelectedId] = useState<string | null>(
    () => window.location.hash.replace('#', '') || null,
  )
  const [detail, setDetail] = useState<CampaignDetail | null>(null)
  const [freshId, setFreshId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ text: string; error?: boolean } | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  const load = useCallback(async (keepSelection = false) => {
    const [nextSummary, nextCampaigns] = await Promise.all([
      api.summary(),
      api.campaigns(),
    ])
    setSummary(nextSummary)
    setCampaigns(nextCampaigns)
    if (!keepSelection && nextCampaigns.length) {
      setSelectedId((current) => current ?? nextCampaigns[0].campaign_id)
    }
    return nextCampaigns
  }, [])

  useEffect(() => {
    load().catch((error: Error) => setNotice({ text: error.message, error: true }))
  }, [load])

  useEffect(() => {
    if (!selectedId) return
    window.location.hash = selectedId
    api
      .campaign(selectedId)
      .then(setDetail)
      .catch((error: Error) => setNotice({ text: error.message, error: true }))
  }, [selectedId])

  async function handleInject() {
    setBusy(true)
    setNotice({ text: 'Injecting a live password-spray campaign…' })
    try {
      const result = await api.inject(45)
      await load(true)
      if (result.campaign) {
        setSelectedId(result.campaign.campaign_id)
        setFreshId(result.campaign.campaign_id)
        setTimeout(() => setFreshId(null), 2000)
        setNotice({
          text: `Injected ${result.injected_events} events against ${result.accounts_targeted} accounts from ${result.source_ip} — detected as ${result.campaign.campaign_id} (${result.campaign.tier}).`,
        })
      } else {
        setNotice({ text: 'Injected, but no campaign formed.', error: true })
      }
    } catch (error) {
      setNotice({ text: (error as Error).message, error: true })
    } finally {
      setBusy(false)
    }
  }

  async function handleUpload(file: File) {
    setBusy(true)
    setNotice({ text: `Analysing ${file.name}…` })
    try {
      const result = await api.upload(file)
      setSelectedId(null)
      setDetail(null)
      await load()
      setNotice({
        text: `${file.name}: ${result.total_events.toLocaleString()} events (${result.source_format} format) → ${result.campaigns} campaigns.`,
      })
    } catch (error) {
      setNotice({ text: (error as Error).message, error: true })
    } finally {
      setBusy(false)
    }
  }

  async function handleReset() {
    setBusy(true)
    try {
      await api.reset()
      setSelectedId(null)
      setDetail(null)
      await load()
      setNotice({ text: 'Reset to the generated dataset.' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>SprayTrace</h1>
          <span className="tag">explainable attack reconstruction</span>
        </div>
        <div className="topbar-actions">
          {busy && <span className="spinner" />}
          <input
            ref={fileInput}
            type="file"
            accept=".csv"
            hidden
            onChange={(event) => {
              const file = event.target.files?.[0]
              if (file) void handleUpload(file)
              event.target.value = ''
            }}
          />
          <button className="btn" onClick={() => fileInput.current?.click()} disabled={busy}>
            Upload CSV
          </button>
          <button className="btn" onClick={() => void handleReset()} disabled={busy}>
            Reset
          </button>
          <button className="btn btn-primary" onClick={() => void handleInject()} disabled={busy}>
            Launch attack
          </button>
        </div>
      </header>

      <StatBar summary={summary} />

      {notice && (
        <div className={`banner ${notice.error ? 'error' : ''}`}>{notice.text}</div>
      )}

      <div className="panes">
        <CampaignList
          campaigns={campaigns}
          selectedId={selectedId}
          freshId={freshId}
          onSelect={setSelectedId}
        />
        <CampaignDetailPane detail={detail} />
      </div>
    </div>
  )
}
