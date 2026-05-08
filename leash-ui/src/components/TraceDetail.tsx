import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { formatDuration, shortId } from '../format'

type Span = Record<string, unknown> & {
  span_id?: number | string
  parent_id?: number | string
  name?: string
  resource?: string
  service?: string
  start?: number  // APM — nanoseconds
  start_ns?: number  // LLMObs
  duration?: number
  error?: number
  status?: string
  meta?: Record<string, unknown>
}

type Node = { span: Span; depth: number }

function startOf(s: Span): number {
  return (s.start_ns ?? s.start ?? 0) as number
}

function idStr(v: unknown): string {
  if (v === null || v === undefined) return ''
  return String(v)
}

function buildTree(spans: Span[]): Node[] {
  if (spans.length === 0) return []
  const byId = new Map<string, Span>()
  for (const s of spans) byId.set(idStr(s.span_id), s)
  const childrenByParent = new Map<string, Span[]>()
  const roots: Span[] = []
  for (const s of spans) {
    const parentId = idStr(s.parent_id)
    if (!parentId || parentId === '0' || !byId.has(parentId)) {
      roots.push(s)
    } else {
      const arr = childrenByParent.get(parentId) ?? []
      arr.push(s)
      childrenByParent.set(parentId, arr)
    }
  }
  const out: Node[] = []
  const visit = (s: Span, depth: number) => {
    out.push({ span: s, depth })
    const children = (childrenByParent.get(idStr(s.span_id)) ?? []).slice()
    children.sort((a, b) => startOf(a) - startOf(b))
    for (const c of children) visit(c, depth + 1)
  }
  roots.sort((a, b) => startOf(a) - startOf(b))
  for (const r of roots) visit(r, 0)
  return out
}

function spanStatus(s: Span): 'ok' | 'error' {
  if (s.status === 'error') return 'error'
  if (typeof s.error === 'number' && s.error !== 0) return 'error'
  return 'ok'
}

export function TraceDetail({ traceId, source }: { traceId: string; source: 'apm' | 'llmobs' }) {
  const [spans, setSpans] = useState<Span[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .getTrace(traceId, source)
      .then((d) => {
        if (!cancelled) setSpans(d.spans as Span[])
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      })
    return () => {
      cancelled = true
    }
  }, [traceId, source])

  const tree = useMemo(() => (spans ? buildTree(spans) : []), [spans])
  const totalStart = tree.length ? startOf(tree[0].span) : 0
  const totalDuration = tree.length
    ? Math.max(
        ...tree.map((n) => startOf(n.span) + (n.span.duration ?? 0) - totalStart),
      )
    : 0

  if (error) return <div className="trace-detail error">error: {error}</div>
  if (spans === null) return <div className="trace-detail loading">loading…</div>
  if (spans.length === 0) return <div className="trace-detail empty-sm">no spans for this trace</div>

  return (
    <div className="trace-detail">
      <div className="trace-detail-head">
        <span className="mono">trace {shortId(traceId)}</span>
        <span>·</span>
        <span>{spans.length} spans</span>
        <span>·</span>
        <span>{formatDuration(totalDuration)}</span>
      </div>
      <div className="span-tree">
        {tree.map(({ span, depth }, i) => {
          const dur = (span.duration ?? 0) as number
          const offset = startOf(span) - totalStart
          const leftPct = totalDuration > 0 ? (offset / totalDuration) * 100 : 0
          const widthPct = totalDuration > 0 ? Math.max(0.5, (dur / totalDuration) * 100) : 100
          const status = spanStatus(span)
          const name = span.name || '(unnamed)'
          const resource = span.resource && span.resource !== name ? span.resource : ''
          return (
            <div key={i} className={`span-row status-${status}`}>
              <div className="span-name" style={{ paddingLeft: `${depth * 14}px` }}>
                <span className="span-label mono">{name}</span>
                {resource && <span className="span-resource mono">{resource}</span>}
                {span.service && <span className="span-service">{span.service}</span>}
              </div>
              <div className="span-bar-wrap">
                <div
                  className="span-bar"
                  style={{ left: `${leftPct}%`, width: `${widthPct}%` }}
                  title={`${name} — ${formatDuration(dur)}`}
                />
              </div>
              <div className="span-duration mono">{formatDuration(dur)}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
