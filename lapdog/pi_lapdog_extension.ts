/**
 * Lapdog Extension for Pi Coding Agent
 *
 * Sends agent lifecycle events to the dd-apm-test-agent (lapdog) for
 * LLM Observability tracing. Creates LLMObs spans for:
 *   - Agent turns (root agent span per user prompt → agent_end)
 *   - LLM calls (assistant message_start → message_end with token usage)
 *   - Tool executions (tool_execution_start → tool_execution_end)
 *
 * Each LLM call also carries a context-window breakdown (system prompt, tool
 * definitions, tool calls, skills, messages) computed by buildTokenBreakdown(),
 * adapted from pi-context-inspector (see the notice below).
 *
 * Install: copy to ~/.pi/agent/extensions/lapdog.ts
 * Configure: set LAPDOG_URL to override the default http://localhost:8126
 *
 * All HTTP posts are fire-and-forget with a 2 s timeout so a lapdog outage
 * never blocks the agent.
 */

import { convertToLlm, estimateTokens, type ExtensionAPI } from "@mariozechner/pi-coding-agent";

const LAPDOG_URL = process.env.LAPDOG_URL || "http://localhost:8126";
const LAPDOG_SESSION_TOKEN = process.env.LAPDOG_SESSION_TOKEN || "";
const HOOKS_ENDPOINT = `${LAPDOG_URL}/pi/hooks`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fire-and-forget POST. Errors are silently swallowed. */
type CwdContext = {
	cwd?: string;
	sessionManager?: {
		getCwd?: () => string;
	};
};

function getCwd(ctx?: CwdContext): string {
	try {
		const cwd = ctx?.cwd || ctx?.sessionManager?.getCwd?.();
		return cwd || process.cwd();
	} catch {
		return process.cwd();
	}
}

function post(event: string, sessionId: string, data: Record<string, unknown>, ctx?: CwdContext): void {
	try {
		fetch(HOOKS_ENDPOINT, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				hook_event_name: event,
				session_id: sessionId,
				lapdog_session_token: LAPDOG_SESSION_TOKEN || undefined,
				cwd: getCwd(ctx),
				...data,
			}),
			signal: AbortSignal.timeout(2000),
		}).catch(() => {});
	} catch {
		// fetch itself can throw synchronously in some edge cases
	}
}

// ---------------------------------------------------------------------------
// Context breakdown
// ---------------------------------------------------------------------------
//
// isSkillPath(), isSkillReadToolCall() and buildTokenBreakdown() are adapted
// from pi-context-inspector v1.3.0 (src/index.ts),
// https://github.com/yuriteixeira/pi-context-inspector, under the MIT License
// reproduced below. Changes: buildTokenBreakdown() takes the call's token total
// and window directly and returns only the fields lapdog reports (no compaction
// reserve or free-space figures), and the types are loosened for this file.
//
// MIT License
//
// Copyright (c) 2026 Yuri Teixeira
// Copyright (c) 2026 YuGiMob
// Copyright (c) 2026 Agnish Chakraborty
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

type ToolDefinitionView = { name: string; description?: string; parameters?: unknown };
type BreakdownEntry =
	| { type: "message"; message: unknown }
	| { type: "compaction"; summary: string }
	| { type: "branch_summary"; summary: string };
type ContextWindowSource = {
	model?: { contextWindow?: number };
	getContextUsage?: () => { contextWindow: number } | undefined;
};
type BreakdownBlock = {
	type?: string;
	text?: string;
	thinking?: string;
	id?: string;
	name?: string;
	arguments?: { path?: unknown };
};
type BreakdownMessage = {
	role?: string;
	content?: string | BreakdownBlock[];
	toolCallId?: string;
	command?: string;
	output?: string;
};

const ESTIMATED_IMAGE_CHARS = 4800;

function isSkillPath(path: unknown): boolean {
	if (typeof path !== "string") return false;
	return /(^|\/)\.agents\/skills\/|(^|\/)\.pi\/agent\/.*\/skills\/|(^|\/)skills\/[^/]+\/SKILL\.md$/i.test(path);
}

function isSkillReadToolCall(block: BreakdownBlock): boolean {
	if (block.name !== "read") return false;
	return isSkillPath(block.arguments?.path);
}

/**
 * Split `tokens` (the call's real prompt size) across context categories.
 * Each category is estimated from raw text (chars / 4, with Pi's own
 * per-message estimator), then all are scaled by one ratio to sum to `tokens`.
 */
function buildTokenBreakdown(
	systemPrompt: string,
	activeToolDefs: ToolDefinitionView[],
	entries: BreakdownEntry[],
	tokens: number,
	contextWindow: number,
): Record<string, number> {
	const estimateChars = (text: string) => Math.ceil(text.length / 4);

	const systemRaw = estimateChars(systemPrompt);
	const toolDefsRaw = estimateChars(JSON.stringify(activeToolDefs));

	let msgTokensRaw = 0;
	let toolsRaw = 0;
	let skillsRaw = 0;
	const skillToolCallIds = new Set<string>();

	for (const entry of entries) {
		if (entry.type === "message") {
			const message = entry.message as BreakdownMessage;
			const messageTotal = estimateTokens(entry.message as Parameters<typeof estimateTokens>[0]);
			const weights = { messages: 0, tools: 0, skills: 0 };
			const blocks = Array.isArray(message.content) ? message.content : [];

			if (message.role === "user" || message.role === "custom") {
				if (typeof message.content === "string") {
					weights.messages += estimateChars(message.content);
				} else {
					for (const block of blocks) {
						if (block.type === "text") weights.messages += estimateChars(block.text ?? "");
						else if (block.type === "image") weights.messages += ESTIMATED_IMAGE_CHARS;
					}
				}
			} else if (message.role === "assistant") {
				for (const block of blocks) {
					if (block.type === "text") weights.messages += estimateChars(block.text ?? "");
					else if (block.type === "thinking") weights.messages += estimateChars(block.thinking ?? "");
					else if (block.type === "toolCall") {
						if (isSkillReadToolCall(block)) {
							weights.skills += estimateChars(JSON.stringify(block));
							if (block.id) skillToolCallIds.add(block.id);
						} else {
							weights.tools += estimateChars(JSON.stringify(block));
						}
					}
				}
			} else if (message.role === "toolResult") {
				const isSkillResult = skillToolCallIds.has(message.toolCallId ?? "");
				for (const block of blocks) {
					if (block.type === "text") {
						if (isSkillResult) weights.skills += estimateChars(block.text ?? "");
						else weights.tools += estimateChars(block.text ?? "");
					}
				}
			} else if (message.role === "bashExecution") {
				weights.tools += estimateChars(message.command ?? "") + estimateChars(message.output ?? "");
			}

			const weightSum = weights.messages + weights.tools + weights.skills;
			if (weightSum > 0) {
				const scale = messageTotal / weightSum;
				msgTokensRaw += weights.messages * scale;
				toolsRaw += weights.tools * scale;
				skillsRaw += weights.skills * scale;
			}
		} else {
			msgTokensRaw += estimateChars(entry.summary);
		}
	}

	const totalRaw = systemRaw + skillsRaw + toolDefsRaw + msgTokensRaw + toolsRaw;
	const ratio = totalRaw > 0 ? tokens / totalRaw : 1;

	const exact = {
		systemPrompt: systemRaw * ratio,
		systemTools: toolDefsRaw * ratio,
		tools: toolsRaw * ratio,
		skills: skillsRaw * ratio,
		messages: msgTokensRaw * ratio,
	};
	const allocated = { systemPrompt: 0, systemTools: 0, tools: 0, skills: 0, messages: 0 };
	let remainder = tokens;
	const keys = Object.keys(exact) as (keyof typeof exact)[];
	for (const key of keys) {
		const value = Math.floor(exact[key]);
		allocated[key] = value;
		remainder -= value;
	}
	if (totalRaw > 0) {
		const byFraction = [...keys].sort((a, b) => (exact[b] % 1) - (exact[a] % 1));
		for (const key of byFraction) {
			if (remainder <= 0) break;
			allocated[key] += 1;
			remainder -= 1;
		}
	}

	return {
		total: tokens,
		contextWindow,
		...allocated,
		other: Math.max(
			0,
			tokens -
				(allocated.systemPrompt + allocated.systemTools + allocated.tools + allocated.skills + allocated.messages),
		),
	};
}

/**
 * Wrap the AgentMessage[] from the `context` event as the entries
 * buildTokenBreakdown() expects. These are exactly the messages sent to the
 * model, with compaction and branch summaries inlined; the session branch
 * would still hold messages a compaction replaced.
 */
function toBreakdownEntries(messages: unknown[]): BreakdownEntry[] {
	return messages.map((message) => {
		const m = message as { role?: string; summary?: string };
		if (m?.role === "compactionSummary") return { type: "compaction", summary: m.summary ?? "" };
		if (m?.role === "branchSummary") return { type: "branch_summary", summary: m.summary ?? "" };
		return { type: "message", message };
	});
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

	// True when the upcoming agent_start was triggered by a genuine user prompt
	// (`before_agent_start` fires only via agent-session.prompt(), never via
	// agent.continue()). When false, the agent_start is a continuation of the
	// current turn (e.g. after auto-compaction or auto-retry) and must NOT spawn
	// a new, input-less trace.
	let userTurnPending = false;

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
	// Same `context` snapshot before convertToLlm(), shaped for buildTokenBreakdown().
	let pendingContextEntries: BreakdownEntry[] = [];

	/** Window size of the active model, from Pi's model registry (0 if unknown). */
	function contextWindowFor(ctx: ContextWindowSource): number {
		try {
			return ctx.model?.contextWindow || ctx.getContextUsage?.()?.contextWindow || 0;
		} catch {
			return 0;
		}
	}

	/** Context breakdown for one LLM call, or undefined when it can't be computed. */
	function computeContextBreakdown(
		usage: { input?: number; cacheRead?: number; cacheWrite?: number } | undefined,
		ctx: ContextWindowSource,
	): Record<string, number> | undefined {
		if (!usage) return undefined;
		// Total prompt size for this call: Anthropic reports cached tokens outside `input`.
		const tokens = (usage.input ?? 0) + (usage.cacheRead ?? 0) + (usage.cacheWrite ?? 0);
		const contextWindow = contextWindowFor(ctx);
		if (tokens <= 0 || contextWindow <= 0) return undefined;
		try {
			// Only the fields declared to the model; ToolInfo also carries sourceInfo etc.
			const activeNames = new Set(pi.getActiveTools());
			const toolDefs = pi
				.getAllTools()
				.filter((tool) => activeNames.has(tool.name))
				.map((tool) => ({ name: tool.name, description: tool.description, parameters: tool.parameters }));
			return buildTokenBreakdown(currentSystemPrompt, toolDefs, pendingContextEntries, tokens, contextWindow);
		} catch {
			return undefined;
		}
	}

	// ------------------------------------------------------------------
	// Session lifecycle
	// ------------------------------------------------------------------

	pi.on("session_start", (_event, ctx) => {
		sessionId = ctx.sessionManager.getSessionId();
		process.env.PI_SESSION_ID = sessionId;
		const model = ctx.model;
		if (model) {
			currentModel = model.id;
			currentProvider = model.provider;
		}
		post("session_start", sessionId, {
			model: model ? `${model.provider}/${model.id}` : "",
			model_provider: currentProvider,
			model_id: currentModel,
		}, ctx);
	});

	pi.on("session_shutdown", (_event?: unknown, ctx?: CwdContext) => {
		post("session_shutdown", sessionId, {}, ctx);
	});

	// ------------------------------------------------------------------
	// Model changes
	// ------------------------------------------------------------------

	pi.on("model_select", (event, ctx) => {
		currentModel = event.model.id;
		currentProvider = event.model.provider;
		post("model_select", sessionId, {
			model: `${event.model.provider}/${event.model.id}`,
			model_provider: event.model.provider,
			model_id: event.model.id,
			previous_model: event.previousModel
				? `${event.previousModel.provider}/${event.previousModel.id}`
				: undefined,
		}, ctx);
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
		// `before_agent_start` only fires for user-initiated prompts and carries
		// the (expanded) prompt text. Use it as the authoritative "new turn"
		// signal so the following agent_start is treated as a real turn, while
		// agent.continue()'s agent_start (no before_agent_start) reads as a
		// continuation.
		userTurnPending = true;
		const prompt = _event?.prompt;
		if (typeof prompt === "string" && prompt) {
			pendingUserPrompt = prompt;
		}
	});

	pi.on("agent_start", (_event, ctx) => {
		// A continuation is an agent_start with no preceding before_agent_start
		// (i.e. agent.continue() after auto-compaction / auto-retry). These belong
		// to the same user turn and must not start a fresh, input-less trace.
		const isContinuation = !userTurnPending;
		post("agent_start", sessionId, {
			user_prompt: pendingUserPrompt,
			is_continuation: isContinuation,
			model: `${currentProvider}/${currentModel}`,
			model_provider: currentProvider,
			model_id: currentModel,
			system_prompt: currentSystemPrompt,
		}, ctx);
		userTurnPending = false;
		if (!isContinuation) {
			pendingUserPrompt = "";
		}
	});

	pi.on("agent_end", (event, ctx) => {
		post("agent_end", sessionId, {
			messages: event.messages,
		}, ctx);
	});

	// ------------------------------------------------------------------
	// Turn lifecycle
	// ------------------------------------------------------------------

	pi.on("turn_start", (event, ctx) => {
		post("turn_start", sessionId, {
			turn_index: event.turnIndex,
			timestamp: event.timestamp,
		}, ctx);
	});

	pi.on("turn_end", (event, ctx) => {
		post("turn_end", sessionId, {
			turn_index: event.turnIndex,
		}, ctx);
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
		pendingContextEntries = toBreakdownEntries(event.messages);
	});

	// ------------------------------------------------------------------
	// LLM message lifecycle (creates LLM spans)
	// ------------------------------------------------------------------

	pi.on("message_start", (event, ctx) => {
		if (event.message.role !== "assistant") return;
		post("message_start", sessionId, {
			message_role: "assistant",
			system_prompt: currentSystemPrompt,
			// Snapshot of the conversation that will be sent to the model for
			// this LLM call. Used to populate input.messages on the LLM span.
			messages: pendingContextMessages,
		}, ctx);
	});

	pi.on("message_end", (event, ctx) => {
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
			errorMessage?: string;
		};

		post("message_end", sessionId, {
			message_role: "assistant",
			model_id: msg.model || currentModel,
			model_provider: msg.provider || currentProvider,
			api: msg.api,
			usage: msg.usage ?? null,
			stop_reason: msg.stopReason ?? "",
			// pi sets errorMessage when stopReason is "error" (or "aborted").
			// Forward it so the LLM span can be marked as an error with detail.
			error_message: msg.errorMessage ?? "",
			content: msg.content,
			context_breakdown: computeContextBreakdown(msg.usage, ctx),
			// Sent even when the breakdown can't be computed so lapdog never falls back to a guessed window.
			context_window: contextWindowFor(ctx) || undefined,
		}, ctx);
	});

	// ------------------------------------------------------------------
	// Tool execution lifecycle (creates tool spans)
	// ------------------------------------------------------------------

	pi.on("tool_execution_start", (event, ctx) => {
		post("tool_execution_start", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			args: event.args,
		}, ctx);
	});

	pi.on("tool_execution_end", (event, ctx) => {
		post("tool_execution_end", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			result: event.result,
			is_error: event.isError,
		}, ctx);
	});

	// ------------------------------------------------------------------
	// Context compaction
	// ------------------------------------------------------------------

	pi.on("session_compact", (event, ctx) => {
		post("session_compact", sessionId, {
			from_extension: event.fromExtension,
		}, ctx);
	});
}
