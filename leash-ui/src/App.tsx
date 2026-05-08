import { useCallback, useEffect, useMemo, useState } from 'react'
import { AppMetricsPanel } from './components/AppMetricsPanel'
import { ColumnHeader, type Kpi } from './components/ColumnHeader'
import { SessionsPanel } from './components/SessionsPanel'
import { TracesList } from './components/TracesList'
import {
  api,
  type AppMetrics,
  type LeashApp,
  type SessionSummary,
  type TraceSummary,
} from './api'
import { formatMs, formatUsd } from './format'
import './App.css'

const APP_ID = 'dundercode'
const REFRESH_MS = 3000

function buildAgentKpis(sessions: SessionSummary[]): Kpi[] {
  const blocked = sessions.find((s) => s.status === 'blocked')
  const running = sessions.find((s) => s.status === 'running')
  const waitMs = sessions.reduce((a, s) => a + s.permission.total_wait_ms, 0)
  const gated = sessions.reduce((a, s) => a + s.permission.gated_call_count, 0)
  const totalCost = sessions.reduce((a, s) => a + s.cost_usd.estimated_total_cost, 0)
  const totalCacheSaved = sessions.reduce((a, s) => a + s.cost_usd.cache_savings, 0)
  const waitTone: Kpi['tone'] = waitMs > 30_000 ? 'bad' : waitMs > 5_000 ? 'warn' : 'ok'

  const statusValue = blocked ? 'blocked' : running ? 'running' : sessions.length ? 'idle' : 'no sessions'
  const statusTone: Kpi['tone'] = blocked ? 'bad' : running ? 'ok' : 'default'
  const statusSub = (blocked ?? running)?.current_task
    ? truncate((blocked ?? running)!.current_task, 60)
    : `${sessions.length} session${sessions.length === 1 ? '' : 's'}`

  return [
    { label: 'Status', value: statusValue, sub: statusSub, tone: statusTone },
    {
      label: 'Permission friction',
      value: formatMs(waitMs),
      sub: `${gated} gated call${gated === 1 ? '' : 's'}`,
      tone: waitTone,
    },
    {
      label: 'Cost',
      value: formatUsd(totalCost),
      sub: totalCacheSaved > 0 ? `saved ${formatUsd(totalCacheSaved)} via cache` : '—',
    },
  ]
}

function truncate(s: string, max: number): string {
  const flat = s.replace(/\s+/g, ' ').trim()
  return flat.length > max ? flat.slice(0, max - 1) + '…' : flat
}

export default function App() {
  const [, setApp] = useState<LeashApp | null>(null)
  const [traces, setTraces] = useState<TraceSummary[]>([])
  const [total, setTotal] = useState(0)
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [metrics, setMetrics] = useState<AppMetrics | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const [a, t, s, m] = await Promise.all([
        api.getApp(APP_ID),
        api.listTraces(APP_ID, 100),
        api.listSessions(APP_ID),
        api.getAppMetrics(APP_ID, 600),
      ])
      setApp(a)
      setTraces(t.traces)
      setTotal(t.total)
      setSessions(s.sessions)
      setMetrics(m)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, REFRESH_MS)
    return () => clearInterval(id)
  }, [refresh])

  const agentKpis = useMemo(() => buildAgentKpis(sessions), [sessions])

  return (
    <div className="leash">
      <header className="top">
        <div className="brand">
          <span className="brand-mark">🦮</span>
          <span className="brand-name">Leash</span>
          <span className="brand-sep">/</span>
          <span className="brand-app">{APP_ID}</span>
        </div>
        <div className="top-meta">
          <span className="pulse-dot" /> live · auto-refresh {REFRESH_MS / 1000}s
          <button className="refresh" onClick={refresh}>refresh</button>
        </div>
      </header>

      {error && <div className="banner error">Error: {error}</div>}

      {loading && sessions.length === 0 && !metrics ? (
        <div className="banner">Loading…</div>
      ) : (
        <div className="dashboard">
          <div className="col col-agent">
            <ColumnHeader title="Coding agent" kpis={agentKpis} />
            <SessionsPanel sessions={sessions} />
          </div>
          <div className="col col-app">
            <ColumnHeader title="Application" kpis={[]} />
            <AppMetricsPanel metrics={metrics} />
            <TracesList traces={traces} total={total} />
          </div>
        </div>
      )}
    </div>
  )
}
