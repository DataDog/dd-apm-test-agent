/**
 * Lapdog Plugin for opencode
 *
 * Sends opencode lifecycle events to the dd-apm-test-agent (lapdog) for
 * LLM Observability tracing. Creates LLMObs spans for:
 *   - Agent turns (root agent span per user prompt → session_idle)
 *   - LLM calls (assistant message.updated with time.completed)
 *   - Tool executions (tool.execute.before → tool.execute.after)
 *
 * Install: copy to ~/.config/opencode/plugin/lapdog.ts
 * (or ${project}/.opencode/plugin/lapdog.ts for a single project).
 * Configure: set LAPDOG_URL to override the default http://localhost:8126.
 *
 * All HTTP posts are fire-and-forget with a 2 s timeout so a lapdog outage
 * never blocks the agent.
 */

import type { Plugin } from "@opencode-ai/plugin";

const LAPDOG_URL = process.env.LAPDOG_URL || "http://localhost:8126";
const HOOKS_ENDPOINT = `${LAPDOG_URL}/opencode/hooks`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fire-and-forget POST. Errors are silently swallowed. */
function post(event: string, sessionId: string, data: Record<string, unknown>): void {
	if (!sessionId) return;
	try {
		fetch(HOOKS_ENDPOINT, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ hook_event_name: event, session_id: sessionId, ...data }),
			signal: AbortSignal.timeout(2000),
		}).catch(() => {});
	} catch {
		// fetch itself can throw synchronously in some edge cases
	}
}

/** Flatten an opencode message body to plain text. */
function extractText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	const parts: string[] = [];
	for (const item of content) {
		if (item && typeof item === "object" && (item as { type?: string }).type === "text") {
			const text = (item as { text?: string }).text;
			if (text) parts.push(text);
		}
	}
	return parts.join("\n");
}

/** Convert a timestamp (ms epoch or ISO) into ns epoch. Returns 0 when unknown. */
function toNs(value: unknown): number {
	if (typeof value === "number" && Number.isFinite(value)) {
		// opencode timestamps are in milliseconds.
		return Math.floor(value * 1_000_000);
	}
	if (typeof value === "string" && value) {
		const ms = Date.parse(value);
		if (!Number.isNaN(ms)) return ms * 1_000_000;
	}
	return 0;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const LapdogPlugin: Plugin = async (ctx) => {
	const completedMessages = new Set<string>();
	const seenSessions = new Set<string>();
	let currentModel = "";
	let currentProvider = "";

	return {
		event: async ({ event }: { event: unknown }) => {
			// The opencode SDK does not publish precise per-event types, so we
			// read fields defensively. The wire format is documented in the
			// dd-apm-test-agent opencode_hooks.py module.
			const e = event as { type?: string; properties?: Record<string, unknown> };
			const t = e?.type ?? "";
			const props = (e?.properties ?? {}) as Record<string, any>;
			const sid: string =
				props.sessionID ?? props.session_id ?? props.sessionId ?? props.info?.id ?? "";

			switch (t) {
				case "session.created": {
					if (sid && !seenSessions.has(sid)) {
						seenSessions.add(sid);
						post("session_start", sid, {
							project: ctx.project?.id ?? "",
							directory: ctx.directory ?? "",
						});
					}
					break;
				}
				case "session.idle":
					post("session_idle", sid, {});
					break;
				case "session.deleted":
				case "session.error":
					post("session_end", sid, { error: props.error });
					break;
				case "session.compacted":
					post("session_compact", sid, { trigger: props.trigger ?? "auto" });
					break;
				case "message.updated": {
					const m = props.message ?? props.info;
					if (!m || !m.id) break;
					const role = m.role;
					const msid: string = sid || m.sessionID || m.session_id || "";
					if (!msid) break;
					if (role === "user") {
						if (!completedMessages.has(m.id)) {
							completedMessages.add(m.id);
							const text = extractText(m.parts ?? m.content);
							post("user_message", msid, { message_id: m.id, content: text });
						}
					} else if (role === "assistant") {
						const completed = m.time?.completed ?? m.completed;
						if (!completed) break;
						if (completedMessages.has(m.id)) break;
						completedMessages.add(m.id);
						const modelId: string = m.modelID ?? m.model ?? "";
						const providerId: string = m.providerID ?? m.provider ?? "";
						if (modelId && modelId !== currentModel) {
							currentModel = modelId;
							currentProvider = providerId || currentProvider;
							post("model_select", msid, {
								model_id: currentModel,
								model_provider: currentProvider,
							});
						}
						post("assistant_message", msid, {
							message_id: m.id,
							model_id: modelId,
							model_provider: providerId,
							tokens: m.tokens ?? {},
							cost: m.cost ?? null,
							start_ns: toNs(m.time?.created ?? m.created),
							end_ns: toNs(completed),
							parts: m.parts ?? [],
							stop_reason: m.stopReason ?? "",
						});
					}
					break;
				}
				default:
					// Other events (file.edited, lsp.*, todo.*, etc.) are not
					// captured in v1.
					break;
			}
		},

		"tool.execute.before": async (input: any, output: any) => {
			const sid: string = input?.sessionID ?? input?.session_id ?? "";
			post("tool_execute_before", sid, {
				tool_call_id: input?.callID ?? input?.call_id ?? "",
				tool_name: input?.tool ?? "",
				args: output?.args ?? {},
			});
		},

		"tool.execute.after": async (input: any, output: any) => {
			const sid: string = input?.sessionID ?? input?.session_id ?? "";
			const err = output?.error;
			post("tool_execute_after", sid, {
				tool_call_id: input?.callID ?? input?.call_id ?? "",
				tool_name: input?.tool ?? "",
				args: input?.args ?? {},
				result: output?.output ?? output?.result ?? "",
				is_error: err !== undefined && err !== null,
				error: err ?? undefined,
			});
		},
	};
};

export default LapdogPlugin;
