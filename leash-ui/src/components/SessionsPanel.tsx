import { useEffect, useState } from 'react'
import type { ContextUsage, GatedTool, SessionSummary, SessionStatus } from '../api'
import { formatElapsed, formatMs, formatRelative, formatTokens, formatUsd, shortId } from '../format'

function taskPreview(p: string, max = 220): string {
  if (!p) return '(no prompt yet)'
  const flat = p.replace(/\s+/g, ' ').trim()
  return flat.length > max ? flat.slice(0, max - 1) + '…' : flat
}

const STATUS_LABEL: Record<SessionStatus, string> = {
  running: 'running',
  idle: 'idle',
  blocked: 'blocked',
}

function useTicker(intervalMs: number, enabled: boolean): number {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!enabled) return
    const id = setInterval(() => setTick((t) => t + 1), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs, enabled])
  return Date.now()
}

function contextTooltipText(c: ContextUsage): string {
  if (!c.breakdown || c.current_tokens === 0) return 'no LLM calls yet'
  const b = c.breakdown
  const pct = (n: number) => (c.current_tokens ? Math.round((n / c.current_tokens) * 100) : 0)
  const lines = [
    `${formatTokens(c.current_tokens)} / ${formatTokens(c.max_tokens)} tokens in the last LLM call`,
    '',
    `cached (reused)   ${formatTokens(b.cached_reused).padStart(7)}  ${pct(b.cached_reused)}%`,
    `new this turn     ${formatTokens(b.new_this_turn).padStart(7)}  ${pct(b.new_this_turn)}%`,
    `newly cached      ${formatTokens(b.newly_cached).padStart(7)}  ${pct(b.newly_cached)}%`,
    '',
    `output            ${formatTokens(b.output).padStart(7)}`,
    `peak this session ${formatTokens(c.peak_tokens).padStart(7)}`,
  ]
  return lines.join('\n')
}

function buildUnblockPrompt(g: GatedTool): string {
  return [
    'I keep getting asked to approve the same tool call. Propose a narrow, safe',
    'allowlist entry for .claude/settings.json `permissions.allow` to cover it,',
    'ask me once to confirm, then apply it. Avoid broad wildcards.',
    '',
    `  tool: ${g.tool_name}`,
    `  sample: ${g.name}`,
    `  approved ${g.count}× (total wait ${formatMs(g.wait_ms)})`,
  ].join('\n')
}

function WrenchIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 1 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  )
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 12l5 5L20 6" />
    </svg>
  )
}

function SessionCard({ s, now }: { s: SessionSummary; now: number }) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const waitSeconds = s.permission.total_wait_ms / 1000
  const frictionTone: 'ok' | 'warn' | 'bad' =
    waitSeconds > 30 ? 'bad' : waitSeconds > 5 ? 'warn' : 'ok'
  const topTools = Object.entries(s.tool_counts).sort(([, a], [, b]) => b - a).slice(0, 6)

  const total = s.cost_usd.estimated_total_cost || 0
  const inPct = total > 0 ? (s.cost_usd.estimated_input_cost / total) * 100 : 0
  const outPct = total > 0 ? (s.cost_usd.estimated_output_cost / total) * 100 : 0
  const inputTokens = s.tokens.input_tokens
  const cachePct = inputTokens > 0 ? (s.tokens.cache_read_input_tokens / inputTokens) * 100 : 0

  const taskElapsed =
    s.current_task_started_ns && s.status !== 'idle'
      ? formatElapsed(now - s.current_task_started_ns / 1_000_000)
      : ''

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1500)
    } catch {
      // Fallback: textarea hack if clipboard API is unavailable.
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand('copy')
        setCopiedKey(key)
        setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1500)
      } finally {
        document.body.removeChild(ta)
      }
    }
  }

  return (
    <div className="session-card">
      <div className="session-head">
        <div className="session-head-left">
          <span className={`status-chip status-${s.status}`}>
            <span className="status-dot" />
            {STATUS_LABEL[s.status]}
            {taskElapsed && <span className="status-elapsed">{taskElapsed}</span>}
          </span>
          <span className="session-model">{s.model || 'unknown model'}</span>
        </div>
        <div className="session-head-right">
          <span className="session-id mono">{shortId(s.session_id, 6, 4)}</span>
          <span className="session-time">{formatRelative(s.started_ns)}</span>
        </div>
      </div>

      <div className="task-block">
        <div className="task-label">
          Current task
          {s.current_task_summary_status === 'pending' && (
            <span className="task-status-hint">summarising…</span>
          )}
          {s.current_task_summary_status === 'error' && (
            <span className="task-status-hint task-status-error">summary unavailable</span>
          )}
        </div>
        {s.current_task_summary ? (
          <>
            <div className="task-summary">{s.current_task_summary}</div>
            <div className="task-raw">{taskPreview(s.current_task || s.first_prompt, 160)}</div>
          </>
        ) : (
          <div className="task-body">{taskPreview(s.current_task || s.first_prompt)}</div>
        )}
        {s.prompt_count > 1 && (
          <div className="task-meta">turn {s.prompt_count}</div>
        )}
      </div>

      <div className="cost-block">
        <div className="cost-head">
          <div className="cost-label">Cost</div>
          <div className="cost-total">{formatUsd(total)}</div>
        </div>
        <div className="cost-bar" aria-hidden="true">
          {total <= 0 ? (
            <div className="cost-bar-empty">no LLM spans yet</div>
          ) : (
            <>
              <div
                className="cost-bar-seg cost-input"
                style={{ width: `${inPct}%` }}
                title={`input ${formatUsd(s.cost_usd.estimated_input_cost)}`}
              />
              <div
                className="cost-bar-seg cost-output"
                style={{ width: `${outPct}%` }}
                title={`output ${formatUsd(s.cost_usd.estimated_output_cost)}`}
              />
            </>
          )}
        </div>
        <div className="cost-legend">
          <span><span className="sw sw-input" /> input {formatUsd(s.cost_usd.estimated_input_cost)}</span>
          <span><span className="sw sw-output" /> output {formatUsd(s.cost_usd.estimated_output_cost)}</span>
        </div>
        {inputTokens > 0 && (
          <div className="cache-row">
            <div className="cache-bar" aria-hidden="true">
              <div className="cache-bar-fill" style={{ width: `${cachePct}%` }} />
            </div>
            <div className="cache-text">
              <strong>{Math.round(cachePct)}%</strong> cache hit
              {s.cost_usd.cache_savings > 0 && (
                <> · saved <strong>{formatUsd(s.cost_usd.cache_savings)}</strong> vs. uncached</>
              )}
            </div>
          </div>
        )}
      </div>

      {s.context.current_tokens > 0 && (
        <div
          className={`context-row tone-${s.context.pct > 85 ? 'bad' : s.context.pct > 60 ? 'warn' : 'ok'}`}
          data-tooltip={contextTooltipText(s.context)}
          title={contextTooltipText(s.context)}
        >
          <div className="context-label">Context</div>
          <div className="context-bar" aria-hidden="true">
            <div className="context-bar-fill" style={{ width: `${Math.min(100, s.context.pct)}%` }} />
          </div>
          <div className="context-text mono">
            {Math.round(s.context.pct)}%
            <span className="context-sub">
              {' '}· {formatTokens(s.context.current_tokens)} / {formatTokens(s.context.max_tokens)}
            </span>
          </div>
        </div>
      )}

      <div className={`friction tone-${frictionTone}`}>
        <div className="friction-head">
          <div className="friction-label">Permission friction</div>
          <div className="friction-total">
            {formatMs(s.permission.total_wait_ms)} · {s.permission.gated_call_count} gated
          </div>
        </div>
        {s.permission.by_tool.length === 0 ? (
          <div className="friction-empty">no permission prompts yet</div>
        ) : (
          <ul className="friction-list">
            {s.permission.by_tool.map((g) => {
              const key = `${s.session_id}:${g.name}`
              const copied = copiedKey === key
              return (
                <li key={g.name}>
                  <span className="friction-name">{g.name}</span>
                  <span className="friction-count">×{g.count}</span>
                  <span className="friction-wait mono">{formatMs(g.wait_ms)}</span>
                  <button
                    type="button"
                    className={`friction-copy${copied ? ' copied' : ''}`}
                    data-tooltip={copied ? 'Copied — paste to your agent' : 'Propose a fix (copies a prompt)'}
                    title={copied ? 'Copied — paste to your agent' : 'Propose a fix (copies a prompt)'}
                    aria-label="propose fix for permission friction"
                    onClick={() => copy(key, buildUnblockPrompt(g))}
                  >
                    {copied ? <CheckIcon /> : <WrenchIcon />}
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {topTools.length > 0 && (
        <div className="tool-chips">
          {topTools.map(([name, count]) => (
            <span key={name} className="chip">
              <span className="chip-name">{name}</span>
              <span className="chip-count">{count}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function SessionsPanel({ sessions }: { sessions: SessionSummary[] }) {
  const hasActive = sessions.some((s) => s.status === 'running' || s.status === 'blocked')
  const now = useTicker(1000, hasActive)

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Sessions</h3>
        <div className="panel-count">{sessions.length}</div>
      </div>
      {sessions.length === 0 ? (
        <div className="empty">
          No Claude Code sessions captured yet. Start Claude Code with hooks enabled and they'll appear here.
        </div>
      ) : (
        <div className="session-list">
          {sessions.map((s) => (
            <SessionCard key={s.session_id} s={s} now={now} />
          ))}
        </div>
      )}
    </section>
  )
}
