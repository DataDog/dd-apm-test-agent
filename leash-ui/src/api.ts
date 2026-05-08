export type LeashApp = {
  id: string
  name: string
  description: string
  repo_path: string
  ml_app: string
  service: string
  focus_codepath: string
  focus_description: string
  trace_count?: number
  span_count?: number
}

export type TraceSummary = {
  trace_id: string
  root_span_id: string
  root_name: string
  root_kind: string
  span_count: number
  start_ns: number
  duration_ns: number
  status: 'ok' | 'error'
  service: string
  ml_app: string
  session_id: string
  kinds: string[]
  source: 'apm' | 'llmobs'
}

export type TracesResponse = {
  app: string
  traces: TraceSummary[]
  total: number
}

export type GatedTool = {
  name: string
  tool_name: string
  count: number
  wait_ms: number
}

export type ModelBreakdown = {
  model: string
  calls: number
  total_tokens: number
  estimated_total_cost_usd: number
}

export type SessionStatus = 'running' | 'idle' | 'blocked'

export type SessionSummary = {
  session_id: string
  trace_id: string
  started_ns: number
  duration_ns: number
  model: string
  status: SessionStatus
  first_prompt: string
  current_task: string
  current_task_started_ns: number | null
  current_task_summary: string | null
  current_task_summary_status: 'idle' | 'pending' | 'done' | 'error'
  prompt_count: number
  tool_call_count: number
  tool_counts: Record<string, number>
  agent_span_count: number
  llm_span_count: number
  permission: {
    total_wait_ms: number
    gated_call_count: number
    by_tool: GatedTool[]
  }
  tokens: {
    input_tokens: number
    output_tokens: number
    cache_read_input_tokens: number
    cache_write_input_tokens: number
    non_cached_input_tokens: number
    total_tokens: number
  }
  cost_usd: {
    estimated_input_cost: number
    estimated_output_cost: number
    estimated_cache_read_input_cost: number
    estimated_cache_write_input_cost: number
    estimated_non_cached_input_cost: number
    estimated_total_cost: number
    cache_savings: number
  }
  models: ModelBreakdown[]
  context: ContextUsage
  in_progress: boolean
}

export type ContextUsage = {
  current_tokens: number
  peak_tokens: number
  max_tokens: number
  pct: number
  breakdown: {
    cached_reused: number
    new_this_turn: number
    newly_cached: number
    output: number
  } | null
}

export type SessionsResponse = {
  app: string
  sessions: SessionSummary[]
}

export type AppMetrics = {
  app: string
  window_s: number
  req_count: number
  err_count: number
  error_rate: number
  rps: number
  p50_ns: number
  p95_ns: number
  p99_ns: number
  top_endpoints: { resource: string; count: number; errors: number; total_duration_ns: number }[]
  timeseries: { t_ns: number; count: number; errors: number }[]
  source: string
}

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return (await res.json()) as T
}

export const api = {
  getApp: (appId: string) => fetch(`/leash/api/apps/${appId}`).then(j<LeashApp>),
  listTraces: (appId: string, limit = 50) =>
    fetch(`/leash/api/traces?app=${encodeURIComponent(appId)}&limit=${limit}`).then(j<TracesResponse>),
  listSessions: (appId: string) =>
    fetch(`/leash/api/sessions?app=${encodeURIComponent(appId)}`).then(j<SessionsResponse>),
  getAppMetrics: (appId: string, windowS = 300) =>
    fetch(`/leash/api/app_metrics?app=${encodeURIComponent(appId)}&window_s=${windowS}`).then(j<AppMetrics>),
  getTrace: (traceId: string, source: 'apm' | 'llmobs') =>
    fetch(`/leash/api/trace/${encodeURIComponent(traceId)}?source=${source}`).then(
      j<{ source: string; trace_id: string; spans: Record<string, unknown>[] }>,
    ),
}
