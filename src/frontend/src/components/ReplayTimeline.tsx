/** Scrub or play the campaign forward in time.
 *
 * Shows the attack arriving rather than sitting finished: the bar fills, the
 * account count climbs, and a successful sign-in lands as a red marker. The
 * point an analyst cares about is the moment breadth becomes obvious.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import type { CampaignDetail } from '../types'

interface Props {
  detail: CampaignDetail
  onCursorChange?: (reachedIndex: number) => void
}

export function ReplayTimeline({ detail, onCursorChange }: Props) {
  const events = useMemo(
    () =>
      [...detail.events].sort(
        (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
      ),
    [detail],
  )

  const [cursor, setCursor] = useState(events.length)
  const [playing, setPlaying] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(() => {
    setCursor(events.length)
    setPlaying(false)
  }, [events])

  useEffect(() => {
    onCursorChange?.(cursor)
  }, [cursor, onCursorChange])

  useEffect(() => {
    if (!playing) return
    // ~4s for the whole campaign regardless of length, so a 2-event travel
    // pair and a 100-event spray both read at a watchable pace.
    const step = Math.max(16, Math.floor(4000 / Math.max(events.length, 1)))
    timer.current = window.setInterval(() => {
      setCursor((current) => {
        if (current >= events.length) {
          setPlaying(false)
          return current
        }
        return current + 1
      })
    }, step)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [playing, events.length])

  if (events.length === 0) return null

  const reached = events.slice(0, cursor)
  const accounts = new Set(reached.map((event) => event.username)).size
  const sources = new Set(reached.map((event) => event.source_ip)).size
  const succeeded = reached.filter((event) => event.success).length
  const start = Date.parse(events[0].timestamp)
  const end = Date.parse(events[events.length - 1].timestamp)
  const span = Math.max(end - start, 1)
  const current = reached.length ? Date.parse(reached[reached.length - 1].timestamp) : start

  function handlePlay() {
    if (cursor >= events.length) setCursor(0)
    setPlaying(true)
  }

  return (
    <div className="replay">
      <div className="replay-controls">
        <button
          className="btn btn-small"
          onClick={() => (playing ? setPlaying(false) : handlePlay())}
        >
          {playing ? '❚❚ Pause' : '▶ Replay'}
        </button>
        <input
          type="range"
          min={0}
          max={events.length}
          value={cursor}
          onChange={(event) => {
            setPlaying(false)
            setCursor(Number(event.target.value))
          }}
          className="replay-scrub"
        />
        <span className="replay-clock">
          {new Date(current).toISOString().slice(11, 19)}
        </span>
      </div>

      <div className="replay-track">
        {events.map((event, index) => (
          <span
            key={event.event_id}
            className={[
              'tick',
              index < cursor ? 'on' : '',
              event.success ? 'breach' : '',
            ]
              .filter(Boolean)
              .join(' ')}
            style={{ left: `${((Date.parse(event.timestamp) - start) / span) * 100}%` }}
            title={`${event.timestamp} · ${event.username} · ${
              event.success ? 'success' : 'failed'
            }`}
          />
        ))}
        <span
          className="playhead"
          style={{ left: `${(cursor / events.length) * 100}%` }}
        />
      </div>

      <div className="replay-counters">
        <span>{reached.length} / {events.length} events</span>
        <span>{accounts} accounts</span>
        <span>{sources} source{sources === 1 ? '' : 's'}</span>
        {succeeded > 0 && <span className="warn">{succeeded} succeeded</span>}
      </div>
    </div>
  )
}
