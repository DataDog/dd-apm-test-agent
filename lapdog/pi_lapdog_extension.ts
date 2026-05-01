/**
 * Lapdog Extension for Pi Coding Agent
 *
 * Sends agent lifecycle events to the dd-apm-test-agent (lapdog) for
 * LLM Observability tracing. Creates LLMObs spans for:
 *   - Agent turns (root agent span per user prompt → agent_end)
 *   - LLM calls (assistant message_start → message_end with token usage)
 *   - Tool executions (tool_execution_start → tool_execution_end)
 *
 * Install: copy to ~/.pi/agent/extensions/lapdog.ts
 * Configure: set LAPDOG_URL to override the default http://localhost:8126
 *
 * All HTTP posts are fire-and-forget with a 2 s timeout so a lapdog outage
 * never blocks the agent.
 */

import { convertToLlm, type ExtensionAPI } from "@mariozechner/pi-coding-agent";

const LAPDOG_URL = process.env.LAPDOG_URL || "http://localhost:8126";
const HOOKS_ENDPOINT = `${LAPDOG_URL}/pi/hooks`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fire-and-forget POST. Errors are silently swallowed. */
function post(event: string, sessionId: string, data: Record<string, unknown>): void {
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

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

// Pi LLM message types after `convertToLlm()`. Pi reduces every extended
// AgentMessage type (bashExecution, custom, branchSummary, compactionSummary)
// down to one of these three, so this matches what's actually sent to the
// model.
type TextContent = { type: "text"; text: string };
type ImageContent = { type: "image"; data: string; mimeType: string };

type LlmMessage =
	| { role: "user"; content: string | (TextContent | ImageContent)[] }
	| { role: "assistant"; content: unknown[] }
	| {
			role: "toolResult";
			toolCallId: string;
			toolName: string;
			content: (TextContent | ImageContent)[];
			isError?: boolean;
		};

export default function lapdog(pi: ExtensionAPI): void {
	let sessionId = "";
	let currentModel = "";
	let currentProvider = "";

	// Track the user prompt that started the current agent run so we can
	// attach it to the agent_start event (input event fires before agent_start).
	let pendingUserPrompt = "";

	// System prompt for the current turn, captured in before_agent_start.
	// Reused for every LLM call inside the turn so each LLM span can record
	// the system message as part of its input.
	let currentSystemPrompt = "";

	// Most recent LLM-shaped message list captured from the `context` event.
	// `context` fires right before each LLM call with the full AgentMessage[]
	// (including extended types like bashExecution / branchSummary /
	// compactionSummary). We feed it through pi's own `convertToLlm()` so the
	// snapshot matches what the provider actually receives.
	let pendingContextMessages: LlmMessage[] = [];

	// ------------------------------------------------------------------
	// Session lifecycle
	// ------------------------------------------------------------------

	pi.on("session_start", (_event, ctx) => {
		sessionId = ctx.sessionManager.getSessionId();
		const model = ctx.model;
		if (model) {
			currentModel = model.id;
			currentProvider = model.provider;
		}
		post("session_start", sessionId, {
			model: model ? `${model.provider}/${model.id}` : "",
			model_provider: currentProvider,
			model_id: currentModel,
		});
	});

	pi.on("session_shutdown", () => {
		post("session_shutdown", sessionId, {});
	});

	// ------------------------------------------------------------------
	// Model changes
	// ------------------------------------------------------------------

	pi.on("model_select", (event) => {
		currentModel = event.model.id;
		currentProvider = event.model.provider;
		post("model_select", sessionId, {
			model: `${event.model.provider}/${event.model.id}`,
			model_provider: event.model.provider,
			model_id: event.model.id,
			previous_model: event.previousModel
				? `${event.previousModel.provider}/${event.previousModel.id}`
				: undefined,
		});
	});

	// ------------------------------------------------------------------
	// User input → agent turn lifecycle
	// ------------------------------------------------------------------

	pi.on("input", (event) => {
		pendingUserPrompt = event.text;
	});

	pi.on("before_agent_start", (_event, ctx) => {
		// Capture the resolved system prompt for this turn so we can attach
		// it to every LLM span in the turn. `event.systemPrompt` reflects the
		// chained prompt as of this handler; ctx.getSystemPrompt() is the
		// same value and works as a fallback.
		try {
			currentSystemPrompt = _event?.systemPrompt ?? ctx.getSystemPrompt() ?? "";
		} catch {
			currentSystemPrompt = "";
		}
	});

	pi.on("agent_start", () => {
		post("agent_start", sessionId, {
			user_prompt: pendingUserPrompt,
			model: `${currentProvider}/${currentModel}`,
			model_provider: currentProvider,
			model_id: currentModel,
			system_prompt: currentSystemPrompt,
		});
		pendingUserPrompt = "";
	});

	pi.on("agent_end", (event) => {
		post("agent_end", sessionId, {
			messages: event.messages,
		});
	});

	// ------------------------------------------------------------------
	// Turn lifecycle
	// ------------------------------------------------------------------

	pi.on("turn_start", (event) => {
		post("turn_start", sessionId, {
			turn_index: event.turnIndex,
			timestamp: event.timestamp,
		});
	});

	pi.on("turn_end", (event) => {
		post("turn_end", sessionId, {
			turn_index: event.turnIndex,
		});
	});

	// ------------------------------------------------------------------
	// Pre-LLM context (fires before each LLM call)
	// ------------------------------------------------------------------

	pi.on("context", (event) => {
		// `event.messages` is a deep copy of the AgentMessage[] about to be
		// sent to the LLM. Run it through pi's own `convertToLlm()` so we
		// capture the same list the provider sees — bashExecution becomes a
		// formatted user message, custom/branchSummary/compactionSummary are
		// inlined as user text, and `excludeFromContext` bash entries are
		// dropped.
		try {
			pendingContextMessages = convertToLlm(event.messages) as LlmMessage[];
		} catch {
			pendingContextMessages = [];
		}
	});

	// ------------------------------------------------------------------
	// LLM message lifecycle (creates LLM spans)
	// ------------------------------------------------------------------

	pi.on("message_start", (event) => {
		if (event.message.role !== "assistant") return;
		post("message_start", sessionId, {
			message_role: "assistant",
			system_prompt: currentSystemPrompt,
			// Snapshot of the conversation that will be sent to the model for
			// this LLM call. Used to populate input.messages on the LLM span.
			messages: pendingContextMessages,
		});
	});

	pi.on("message_end", (event) => {
		if (event.message.role !== "assistant") return;

		const msg = event.message as {
			role: "assistant";
			content: Array<{ type: string; text?: string; id?: string; name?: string; arguments?: unknown }>;
			model?: string;
			provider?: string;
			api?: string;
			usage?: {
				input: number;
				output: number;
				cacheRead: number;
				cacheWrite: number;
				totalTokens: number;
				cost: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number };
			};
			stopReason?: string;
		};

		post("message_end", sessionId, {
			message_role: "assistant",
			model_id: msg.model || currentModel,
			model_provider: msg.provider || currentProvider,
			api: msg.api,
			usage: msg.usage ?? null,
			stop_reason: msg.stopReason ?? "",
			content: msg.content,
		});
	});

	// ------------------------------------------------------------------
	// Tool execution lifecycle (creates tool spans)
	// ------------------------------------------------------------------

	pi.on("tool_execution_start", (event) => {
		post("tool_execution_start", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			args: event.args,
		});
	});

	pi.on("tool_execution_end", (event) => {
		post("tool_execution_end", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			result: event.result,
			is_error: event.isError,
		});
	});

	// ------------------------------------------------------------------
	// Context compaction
	// ------------------------------------------------------------------

	pi.on("session_compact", (event) => {
		post("session_compact", sessionId, {
			from_extension: event.fromExtension,
		});
	});
}
