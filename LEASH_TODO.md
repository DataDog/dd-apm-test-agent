# Leash — Open Problems & TODO

A running list of problems that need to be solved before Leash is a real
product. Each item is a rough problem statement plus the current leading
proposal. Edit freely — this is a working doc, not a spec.

---

## 1. Correlate a coding-agent session to its target application

**Problem.** Today Leash pretends every Claude Code session belongs to the
"current" app (hardcoded to dundercode). In reality, users run many
sessions across many repos, and the app-under-work is only identifiable by
context (cwd, prompts, which files are being edited). For Leash's pane of
glass to be meaningful, we need a deterministic way to join a coding
session to the application telemetry that session produces.

**Proposal (KV 2026-04-18).** Ship a Claude Code **skill** (e.g.
`leash-run-app`) that wraps "start the application". When invoked, the
skill exports `DD_TAGS=coding_session_id:<claude-session-uuid>,...` into
the environment of the spawned app process. The app's tracer already
picks up `DD_TAGS`, so every span / log / metric it emits carries the
session id as a tag. Leash's "session view" is then defined as
"everything tagged with this `coding_session_id`" — coding-agent spans
from hooks + APM/OTel telemetry from the target app — fused into one
timeline.

**Open questions.**
- How does the skill discover the *current* Claude Code session id? A
  hook can read `$CLAUDE_SESSION_ID` or similar; verify what's actually
  exposed to skills.
- Merge strategy when a single coding session starts multiple app
  processes (restart loop, multi-service stack). One tag with the
  session id is probably still the right key, but we need per-run
  grouping inside it.
- Cwd-based fallback for apps that don't honor DD_TAGS / aren't
  instrumented. Do we even try, or do we require instrumentation as
  a precondition?
- Decide whether the skill also registers the app with Leash
  (`POST /leash/api/apps`) so the app card auto-populates instead of
  hardcoding `dundercode`.

---

## 2. Session / span state does not survive test-agent restarts

**Problem.** `ClaudeHooksAPI._sessions` and `_assembled_spans` live only
in-process. The dev loop uses `watchmedo` to auto-restart on any Python
change, which wipes everything. Same thing happens in production-ish use
if the agent crashes. You can't analyse friction for a session that
predates the last restart.

**Proposal.** Persist session state to disk (JSONL under a configurable
dir) and rehydrate on startup. Alternative: narrow `watchmedo`'s pattern
to exclude frequently-edited modules during UI-heavy iterations.

**Open questions.**
- Disk format — append-only events (raw hook payloads) vs. a
  periodically-rewritten snapshot of `_sessions` + `_assembled_spans`.
- Bound on retention. Session logs grow unbounded; need a rotation
  policy.

---

## 3. No real logs / metrics ingestion from the target app

**Problem.** The dashboard's "Application" column derives req/s, error
rate, and p95 from APM traces because OTLP logs/metrics aren't flowing
from dundercode. For a real pane of glass we need the app's actual logs
and metrics alongside its traces.

**Proposal.** Add a `LogsPanel` (tail-style stream) and a real metrics
fetcher that pulls from `/v1/logs` and `/v1/metrics`, filtered by
`service.name`. Instrument dundercode with an OTel Python SDK sending
to the test agent.

**Open questions.**
- Do we recommend OTel or ddtrace for apps under Leash? (Dundercode uses
  ddtrace via ddkypy; traces work but logs/metrics don't reach the test
  agent in the OTel format we're reading.)
- For logs specifically: should Leash also capture app stdout/stderr
  when the app is launched via the `leash-run-app` skill? That avoids
  requiring OTel instrumentation at all.

---

## 4. Eval suggestions and scenario-run loop (the core Leash vision)

**Problem.** Leash's original pitch was "coding agent runs a test
scenario, gets an llm-as-a-judge score from the trace, and iterates
autonomously, and Leash suggests what to evaluate." We have the friction
analyzer as a first taste, but there's no scenario runner and no
eval-suggestion surface yet.

**Proposal.** Two endpoints to build next:
- `POST /leash/api/suggest/evals` — takes app + a codepath of interest,
  returns candidate eval definitions (name, judge prompt, pass
  criteria) grounded in recent traces.
- `POST /leash/api/scenarios/run` — takes an eval + a scenario input,
  executes it against the target app, collects the trace, runs the
  judge, returns score. Repeatable so an agent can iterate.

**Open questions.**
- Storage model for evals (in-memory registry? disk? per-app?).
- Scenario definition shape. Starting point: an HTTP request template
  for HTTP apps like dundercode. More complex later.

---

## 5. Multi-app support / app registry

**Problem.** The app registry in `leash.py` is a hardcoded dict with a
single entry (`dundercode`). Users have many apps.

**Proposal.** File-backed registry (`~/.leash/apps.json`), with a small
CRUD API (`GET/POST/DELETE /leash/api/apps`). The app card becomes a
selector.

**Open questions.**
- Auto-discovery via `service` tags seen on incoming traces?

---

## 6. Coding-agent skill: distribution, auto-activation, persistence

**Problem.** The `leash-iterate` skill at `.claude/skills/` only
auto-loads when Claude Code starts with cwd under the test-agent repo.
For "load once and continue normally" to hold across projects, the skill
needs to live somewhere globally discoverable. Also: the skill's
description alone decides when Claude Code fires it — we need to tune
that wording based on real usage to avoid either missed fires or
over-firing on trivial edits.

**Proposal.**
- Ship a small installer: `scripts/leash-install-skill.sh` symlinks
  `.claude/skills/leash-iterate` into `~/.claude/skills/`. One-shot
  install, source of truth stays in the repo.
- Iterate on the description / trigger wording based on observed fire
  rate (capture via hooks: did the skill fire for sessions where the
  user was clearly editing a tracked app?).
- Consider a companion hook (`PostToolUse` on Edit/Write) that nudges
  the agent to check Leash when it edits a file in a registered app.
  This moves "remember to check the trace" from skill-guidance into
  hard enforcement, if that turns out to matter.

**Open questions.**
- Should the skill also auto-register the app with Leash if it finds a
  tracer configured in the repo? (Tie-in with TODO #1.)
- Should the skill refuse to let the agent declare done until a trace
  has been fetched, or is that too invasive?

---

## 7. Trace detail view should surface instrumentation tags

**Problem.** The UI's expanded trace-detail renders span name, duration,
service and a gantt bar, but does not show `meta` or `metrics` entries.
When an agent adds telemetry (`leash.search.match_count=816`) during an
iteration loop, it has to `curl` the trace JSON to see the new tag — the
pane of glass fails at exactly the moment it should be most useful.

**Proposal.** In `TraceDetail.tsx`, show a per-span foldout of
user-added tags (heuristic: any `meta` / `metrics` key *not* in a known
framework prefix like `_dd.`, `http.`, `component`, `_sampling_priority_v1`,
etc.). Highlight keys under `leash.*` in particular.

---

## 8. Skill needs to remind about external caches (Slack, CDN)

**Problem.** During the unfurl iteration, I exercised `/quote/3691`,
verified the new meta tags via Leash traces, and declared done. But
Slack caches unfurls per URL, so existing messages in Slack would keep
showing the old grey-box preview until Slack refetches. The skill's
"trace is truth" principle is correct locally, but silent about
downstream caches.

**Proposal.** Add a brief "downstream caches" bullet to the skill: when
a change affects a response that external systems (Slack, search
engines, CDN) have already fetched, trace-verification only proves
your server's output changed. You also need to bust the cache or ask
the user to test in a fresh context.

---

## 9. Task summarisation is disabled — needs a non-recursive path

**Problem.** The first cut used `claude-code-sdk` to summarise the
current user prompt into a short task label. Running fine as a UI
feature — but the SDK spawns a fresh Claude Code CLI process, whose
hooks report back to this same test agent. That creates a brand-new
Claude Code session, which Leash then also tries to summarise,
spawning another CLI, forever. Observed as runaway subprocesses and
spiking cost.

**Workaround in place.** `_get_or_schedule_task_summary` short-circuits
to `{"status": "idle", "summary": None}`. UI falls back to the raw
prompt preview automatically (no UI change needed).

**Proposal.**
- Call Anthropic's API directly (via the `anthropic` SDK) instead of
  going through the Claude Code CLI. Budget: hundreds of tokens per
  prompt × cheap haiku → negligible.
- Alternative: if we stay on the CLI, spawn with an env tag like
  `LEASH_INTERNAL=1` and have `claude_hooks.py` refuse to create a
  session state for any hook carrying that tag.

**Open questions.**
- Where should the `ANTHROPIC_API_KEY` come from for the summariser?
  Env var at leash startup, or per-app config?
- Re-evaluate whether the summarisation is even the right feature
  before re-enabling — the raw prompt preview may be enough once
  prompts are short.

---

## 10. watchmedo reloads go stale after hours of runtime

**Problem.** Noticed that after several hours of `scripts/leash-dev.sh`
uptime, `watchmedo auto-restart` stopped picking up Python file touches;
had to `kill -TERM` the child to force a restart. Probably an exhausted
fsevents watcher or a stuck signal handler.

**Proposal.** Either (a) swap to a dev-reload helper that is known-good
on macOS (`uvicorn --reload` pattern, `hupper`, or `watchfiles` as a
library), or (b) add a health signal in `leash-dev.sh` that periodically
verifies the child's pid has been cycled since the most recent `.py`
mtime and emits a warning if not.

---

## 11. Housekeeping / papercuts

- `setup.py` pins `claude-code-sdk>=0.1.0`, but only `0.0.25` exists.
  Loosen the pin and add `claude-code-sdk` to the actual `.venv` (I
  had to install it manually). See the session-friction analyzer for
  where this bites.
- `leash-ui/` pulls deps via `npm install` on first `scripts/leash-dev.sh`
  run. It's ~170 packages; consider a lockfile commit if it's not there
  already.
- `ClaudeHooksAPI` exposes `_sessions` and `_assembled_spans` as
  underscored attributes; Leash reads them directly. Promote these to
  real accessors before either module churns.
