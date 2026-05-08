import type { AppMetrics } from '../api'
import { formatDuration } from '../format'

function Sparkline({ series }: { series: { t_ns: number; count: number; errors: number }[] }) {
  const w = 600
  const h = 40
  const max = Math.max(1, ...series.map((b) => b.count))
  const step = series.length > 1 ? w / (series.length - 1) : w
  const linePts = series
    .map((b, i) => `${i * step},${h - (b.count / max) * (h - 4) - 2}`)
    .join(' ')
  const areaPts = `0,${h} ${linePts} ${w},${h}`
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polygon points={areaPts} fill="var(--accent-dim)" />
      <polyline points={linePts} fill="none" stroke="var(--accent)" strokeWidth="1.5" />
      {series.map((b, i) =>
        b.errors > 0 ? (
          <circle key={i} cx={i * step} cy={h - (b.count / max) * (h - 4) - 2} r="2.5" fill="var(--err)" />
        ) : null,
      )}
    </svg>
  )
}

export function AppMetricsPanel({ metrics }: { metrics: AppMetrics | null }) {
  if (!metrics) {
    return <div className="app-metrics-strip app-metrics-empty">loading telemetry…</div>
  }
  const errTone = metrics.error_rate > 0.05 ? 'bad' : metrics.error_rate > 0 ? 'warn' : 'ok'
  return (
    <div className="app-metrics-strip">
      <div className="app-metrics-spark">
        <Sparkline series={metrics.timeseries} />
      </div>
      <div className="app-metrics-stats">
        <div className="ams-stat">
          <span className="ams-val">{metrics.rps.toFixed(2)}</span>
          <span className="ams-unit">rps</span>
        </div>
        <div className="ams-sep">·</div>
        <div className={`ams-stat tone-${errTone}`}>
          <span className="ams-val">{(metrics.error_rate * 100).toFixed(1)}%</span>
          <span className="ams-unit">err</span>
        </div>
        <div className="ams-sep">·</div>
        <div className="ams-stat">
          <span className="ams-val mono">{formatDuration(metrics.p50_ns)}</span>
          <span className="ams-unit">p50</span>
        </div>
        <div className="ams-stat">
          <span className="ams-val mono">{formatDuration(metrics.p95_ns)}</span>
          <span className="ams-unit">p95</span>
        </div>
        <div className="ams-sep">·</div>
        <div className="ams-stat ams-window">
          <span className="ams-val">{metrics.req_count}</span>
          <span className="ams-unit">req / {Math.round(metrics.window_s / 60)}m</span>
        </div>
      </div>
    </div>
  )
}
