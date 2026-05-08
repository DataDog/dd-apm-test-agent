---
name: leash-iterate
description: Load when editing application code that emits APM traces to the local test agent (Leash). Enforces a telemetry-first iteration loop — after code changes, confirm via Leash trace endpoints rather than stdout — so feedback is short and grounded. Applies to any non-trivial edit in a tracked app; does not apply to config/docs or repos Leash does not know about.
---

# leash-iterate

Leash observes both you (the coding agent) and the application you are
editing. Once loaded, Leash is your default debugging surface. You should
not need to think about invoking it — weave it into the same rhythm as
reading files, running tests, and grepping.

## Core principle — the trace is truth

After a code change, do **not** conclude "it works" from stdout or from a
function's return value. Fetch the trace from Leash and read the span
names, tags, and durations to confirm the change manifests. If the change
is invisible in the trace, it is not observable — instrument it.

## Workflow (inline, not ceremonial)

When you edit a function that is traced, or a codepath that is reached by
a traced entry point:

1. **Before.** Fetch the latest trace for the scenario you will rerun.
   Note the current span tree — names, parent/child, durations, tags.
       curl -s 'http://localhost:8126/leash/api/traces?app=<id>&limit=3'
       curl -s 'http://localhost:8126/leash/api/trace/<trace_id>?source=apm'
2. **Edit.** Change the behavior. If you add a new codepath, add the
   instrumentation that makes it visible: span tags, child spans, logs
   with context.
3. **Exercise.** Run the scenario once (a curl, a function call, a test).
4. **Verify.** Fetch the new trace. Diff against the baseline:
   - New child span where expected?
   - Tags reflect the new behavior?
   - Durations reasonable?
   If the trace does not show the change, the change is not observable.
   Fix that before iterating further.
5. **Iterate.** Repeat 2–4 until the trace reflects intent. Then declare
   done.

## Tagging conventions (be explicit)

Use a `leash.<subject>.<field>` namespace for tags you add as part of an
iteration, so they are easy to grep in traces and do not collide with
tracer-auto tags.

**ddtrace gotcha.** `span.set_tag(key, value)` routes **string** values
into the span's `meta` dict and **numeric** values (int / float) into
the `metrics` dict. When querying the trace, look in both places:

    meta:    {"leash.search.query": "pam jim", "leash.search.strategy": "all_tokens"}
    metrics: {"leash.search.tokens": 2, "leash.search.match_count": 816}

If you forget this you will think your numeric tag didn't apply.

## Endpoint cheatsheet

Base URL: `http://localhost:8126`

| Endpoint | Use |
|---|---|
| `GET /leash/api/apps` | list tracked apps |
| `GET /leash/api/apps/<id>` | app metadata, live trace/span counts |
| `GET /leash/api/traces?app=<id>&limit=N` | recent traces (apm + llmobs) |
| `GET /leash/api/trace/<trace_id>?source=apm\|llmobs` | full span tree |
| `GET /leash/api/app_metrics?app=<id>&window_s=300` | derived p95 / rps / err |
| `GET /leash/api/sessions?app=<id>` | your own coding-session telemetry |
| `POST /leash/api/suggest/permission_friction` | reduce your own approval friction |

## Self-optimise as you go

Leash observes *you* as much as it observes the application. The same
feedback loop that validates app-code changes validates your own
behaviour. Check your own telemetry along the way — not only at task
end:

    curl -s 'http://localhost:8126/leash/api/sessions?app=<id>'
    curl -s -X POST -H 'content-type: application/json' -d '{}' \
        'http://localhost:8126/leash/api/suggest/permission_friction'

Act on what you see:

- **Permission friction.** Tools you repeatedly ask the user to approve.
  If the suggestion endpoint returns concrete allowlist entries, surface
  them to the user as a proposed edit to `.claude/settings.json`.
- **Tool-use patterns.** If you habitually Read then Grep, consider
  whether Grep alone is faster. The `tool_counts` field tells the story.
- **Cache hit ratio.** Low cache hit rates on the LLM spans usually mean
  you are resubmitting a large variable context; find where state could
  be held stable.

## Institutionalise what you learn — write to AGENTS.md

When an iteration teaches you something durable about *this repo* — a
pitfall, a preferred tool order, a safe-to-allow command pattern, a
non-obvious invariant — append one or two sentences to `AGENTS.md` at
the repo root (or `CLAUDE.md` if that is the repo's existing
convention). Create the file if neither exists. Future agents (and
future-you) read it first.

**Good entries.** Terse, durable, unobvious, repo-specific:
- "`dundercode.data.find_lines` is tokenised (all tokens must appear);
  it tags `leash.search.query` in meta and `leash.search.match_count`
  in metrics."
- "This repo uses ddkypy (custom ddtrace fork); get the current span
  via `ddtrace.tracer.current_span()` before setting tags."

**Skip.** Anything enforced by tests, task-level TODOs (use the tracker),
or duplicates of existing CLAUDE.md entries.

Do not make AGENTS.md churn every turn. Write only when the lesson is
generalisable beyond the current task.

## Pure-markup / client-side changes

When a change only affects the HTTP response body (HTML tags, inline
JS/CSS, Open Graph meta) and emits no distinctive span, the server trace
cannot confirm the change — the response body itself is the observable.
Fetch it and grep. This still obeys "the trace is truth" in spirit:
evidence from the actual request, not from your expectation.

A useful side effect: the *baseline* fetch before your edit catches
regressions introduced by *prior* edits that were never exercised. Do
not skip the baseline just because the change is trivial.

## When this does NOT apply

- Edits in repos Leash does not track.
- Config / README / docs-only changes.
- Pure refactors with no behavioral change (use tests, not traces).

## One-time setup (dev responsibility, not agent's)

1. App is registered in Leash (see `_APPS` in
   `ddapm_test_agent/leash.py`).
2. App emits APM traces to `localhost:8126` (`DD_TRACE_AGENT_URL` or
   tracer equivalent).
3. Test agent running with `scripts/leash-dev.sh`.

If any of these are missing, fix setup first; do not fall back to
stdout-only iteration.
