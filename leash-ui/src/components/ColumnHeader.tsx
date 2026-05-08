type Tone = 'default' | 'ok' | 'warn' | 'bad'

export type Kpi = {
  label: string
  value: string
  sub?: string
  tone?: Tone
}

export function ColumnHeader({ title, kpis }: { title: string; kpis: Kpi[] }) {
  return (
    <div className="col-head">
      <h2 className="col-title">{title}</h2>
      {kpis.length > 0 && (
        <div className="col-kpis">
          {kpis.map((k) => (
            <div key={k.label} className={`col-kpi tone-${k.tone ?? 'default'}`}>
              <div className="col-kpi-label">{k.label}</div>
              <div className="col-kpi-value">{k.value}</div>
              {k.sub && <div className="col-kpi-sub">{k.sub}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
