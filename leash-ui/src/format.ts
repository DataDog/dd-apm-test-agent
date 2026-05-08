export function formatDuration(ns: number): string {
  if (!ns) return '0ms'
  if (ns < 1_000) return `${ns}ns`
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)}µs`
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(1)}ms`
  return `${(ns / 1_000_000_000).toFixed(2)}s`
}

export function formatMs(ms: number): string {
  if (!ms) return '0ms'
  if (ms < 1_000) return `${Math.round(ms)}ms`
  return `${(ms / 1_000).toFixed(1)}s`
}

export function formatTime(ns: number): string {
  if (!ns) return '—'
  const d = new Date(ns / 1_000_000)
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0')
}

export function formatElapsed(ms: number): string {
  if (ms < 0 || !isFinite(ms)) return ''
  const s = Math.floor(ms / 1_000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const rs = s % 60
  if (m < 60) return rs > 0 ? `${m}m ${rs}s` : `${m}m`
  const h = Math.floor(m / 60)
  const rm = m % 60
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`
}

export function formatRelative(ns: number): string {
  if (!ns) return ''
  const deltaMs = Date.now() - ns / 1_000_000
  if (deltaMs < 1_000) return 'just now'
  if (deltaMs < 60_000) return `${Math.round(deltaMs / 1_000)}s ago`
  if (deltaMs < 3_600_000) return `${Math.round(deltaMs / 60_000)}m ago`
  return `${Math.round(deltaMs / 3_600_000)}h ago`
}

export function shortId(id: string, head = 8, tail = 4): string {
  if (!id) return ''
  return id.length > head + tail + 2 ? `${id.slice(0, head)}…${id.slice(-tail)}` : id
}

export function formatTokens(n: number): string {
  if (!n) return '0'
  if (n < 1_000) return String(n)
  if (n < 1_000_000) return `${(n / 1_000).toFixed(n < 10_000 ? 1 : 0)}k`
  return `${(n / 1_000_000).toFixed(2)}M`
}

export function formatUsd(n: number): string {
  if (!n) return '$0.00'
  if (n < 0.01) return `$${n.toFixed(4)}`
  if (n < 1) return `$${n.toFixed(3)}`
  return `$${n.toFixed(2)}`
}
