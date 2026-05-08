import { Fragment, useState } from 'react'
import type { TraceSummary } from '../api'
import { formatDuration, formatTime, shortId } from '../format'
import { TraceDetail } from './TraceDetail'

function rowKey(t: TraceSummary): string {
  return `${t.source}-${t.trace_id}`
}

export function TracesList({ traces, total }: { traces: TraceSummary[]; total: number }) {
  const [openKey, setOpenKey] = useState<string | null>(null)

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Traces</h3>
        <div className="panel-count">showing {traces.length} of {total}</div>
      </div>
      {traces.length === 0 ? (
        <div className="empty">
          No traces yet. Run the app with tracing enabled and they'll appear here.
        </div>
      ) : (
        <table className="trace-table">
          <thead>
            <tr>
              <th style={{ width: 24 }}></th>
              <th>Time</th>
              <th>Source</th>
              <th>Trace</th>
              <th>Root span</th>
              <th>Kind</th>
              <th>Spans</th>
              <th>Duration</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {traces.map((t) => {
              const key = rowKey(t)
              const open = key === openKey
              return (
                <Fragment key={key}>
                  <tr
                    className={`trace-row status-${t.status} ${open ? 'open' : ''}`}
                    onClick={() => setOpenKey(open ? null : key)}
                  >
                    <td className="caret">{open ? '▾' : '▸'}</td>
                    <td className="mono">{formatTime(t.start_ns)}</td>
                    <td><span className={`source source-${t.source}`}>{t.source}</span></td>
                    <td className="mono">{shortId(t.trace_id)}</td>
                    <td>{t.root_name}</td>
                    <td><span className="kind">{t.root_kind || '—'}</span></td>
                    <td className="num">{t.span_count}</td>
                    <td className="mono num">{formatDuration(t.duration_ns)}</td>
                    <td>
                      <span className={`status-pill ${t.status}`}>{t.status}</span>
                    </td>
                  </tr>
                  {open && (
                    <tr className="trace-detail-row">
                      <td colSpan={9}>
                        <TraceDetail traceId={t.trace_id} source={t.source} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      )}
    </section>
  )
}
