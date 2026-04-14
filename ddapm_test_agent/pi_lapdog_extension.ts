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

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const LAPDOG_URL = process.env.LAPDOG_URL || "http://localhost:8126";
const HOOKS_ENDPOINT = `${LAPDOG_URL}/pi/hooks`;
const MAX_OUTPUT_BYTES = 128 * 1024; // 128 KB cap for tool output / message content

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(value: unknown, maxBytes: number = MAX_OUTPUT_BYTES): string {
	const str = typeof value === "string" ? value : JSON.stringify(value ?? "");
	if (str.length <= maxBytes) return str;
	return str.slice(0, maxBytes) + `\n... (truncated, ${str.length} bytes total)`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function byteLength(value: unknown): number {
	try {
		return new TextEncoder().encode(JSON.stringify(value ?? null)).length;
	} catch {
		return 0;
	}
}

function pushSection(sections: Array<{ name: string; bytes: number }>, name: string, value: unknown): void {
	if (value === undefined || value === null) return;
	const bytes = byteLength(value);
	if (bytes > 0) sections.push({ name, bytes });
}

function pushOtherSection(
	sections: Array<{ name: string; bytes: number }>,
	value: unknown,
): void {
	const bytes = byteLength(value);
	if (bytes > 0) sections.push({ name: "other", bytes });
}

function normalizeProviderContext(payload: unknown): Array<{ name: string; bytes: number }> {
	if (!isRecord(payload)) return [];

	const sections: Array<{ name: string; bytes: number }> = [];
	const tools = payload.tools;
	pushSection(sections, "tools", tools);

	if (Array.isArray(payload.messages)) {
		const messages = payload.messages.filter(isRecord);
		const systemMessages = messages.filter((m) => m.role === "system" || m.role === "developer");
		const userMessages = messages.filter((m) => m.role === "user");
		const assistantMessages = messages.filter((m) => m.role === "assistant");
		const toolMessages = messages.filter((m) => m.role === "tool");
		const otherMessages = messages.filter(
			(m) => m.role !== "system" && m.role !== "developer" && m.role !== "user" && m.role !== "assistant" && m.role !== "tool",
		);
		pushSection(sections, "system", payload.system ?? systemMessages);
		pushSection(sections, "user_messages", userMessages);
		pushSection(sections, "assistant_messages", assistantMessages);
		pushSection(sections, "tool_messages", toolMessages);
		pushOtherSection(sections, {
			...payload,
			tools: undefined,
			system: undefined,
			messages: otherMessages.length > 0 ? otherMessages : undefined,
		});
		return sections;
	}

	if (Array.isArray(payload.contents)) {
		const contents = payload.contents.filter(isRecord);
		const userMessages = contents.filter((m) => m.role === "user");
		const assistantMessages = contents.filter((m) => m.role === "model");
		const toolMessages = contents.filter((m) => m.role !== "user" && m.role !== "model");
		pushSection(sections, "system", payload.systemInstruction);
		pushSection(sections, "user_messages", userMessages);
		pushSection(sections, "assistant_messages", assistantMessages);
		pushSection(sections, "tool_messages", toolMessages);
		pushOtherSection(sections, {
			...payload,
			tools: undefined,
			systemInstruction: undefined,
			contents: undefined,
		});
		return sections;
	}

	pushSection(sections, "request", payload);
	return sections;
}

function resolvePayloadModel(payload: unknown, currentModel: string): string {
	if (isRecord(payload) && typeof payload.model === "string" && payload.model.length > 0) {
		return payload.model;
	}
	return currentModel;
}

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

export default function lapdog(pi: ExtensionAPI): void {
	let sessionId = "";
	let currentModel = "";
	let currentProvider = "";

	// Track the user prompt that started the current agent run so we can
	// attach it to the agent_start event (input event fires before agent_start).
	let pendingUserPrompt = "";

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

	pi.on("agent_start", () => {
		post("agent_start", sessionId, {
			user_prompt: pendingUserPrompt,
			model: `${currentProvider}/${currentModel}`,
			model_provider: currentProvider,
			model_id: currentModel,
		});
		pendingUserPrompt = "";
	});

	pi.on("agent_end", (event) => {
		// Extract the final assistant text from the last assistant message
		let outputText = "";
		for (let i = event.messages.length - 1; i >= 0; i--) {
			const msg = event.messages[i];
			if (msg.role === "assistant") {
				const textParts = (msg.content as Array<{ type: string; text?: string }>)
					.filter((c) => c.type === "text" && c.text)
					.map((c) => c.text!);
				outputText = textParts.join("\n");
				break;
			}
		}
		post("agent_end", sessionId, {
			output: truncate(outputText),
			num_messages: event.messages.length,
			model_provider: currentProvider,
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
	// Provider request context + LLM message lifecycle
	// ------------------------------------------------------------------

	pi.on("before_provider_request", (event, ctx) => {
		const model = ctx.model;
		if (model) {
			currentModel = model.id;
			currentProvider = model.provider;
		}
		const contextUsage = ctx.getContextUsage();
		const payload = event.payload;
		const modelId = resolvePayloadModel(payload, currentModel);
		post("provider_request_context", sessionId, {
			model_id: modelId,
			model_provider: currentProvider,
			context_window_size: contextUsage?.contextWindow ?? 0,
			estimated_input_tokens: contextUsage?.tokens ?? null,
			sections: normalizeProviderContext(payload),
		});
	});

	pi.on("message_start", (event) => {
		if (event.message.role !== "assistant") return;
		post("message_start", sessionId, {
			message_role: "assistant",
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

		// Extract tool_use blocks for span linking
		const toolCalls = msg.content
			.filter((c) => c.type === "toolCall")
			.map((c) => ({ id: c.id, name: c.name, arguments: c.arguments }));

		// Extract text output
		const textParts = msg.content
			.filter((c) => c.type === "text" && c.text)
			.map((c) => c.text!);

		post("message_end", sessionId, {
			message_role: "assistant",
			model_id: msg.model || currentModel,
			model_provider: msg.provider || currentProvider,
			api: msg.api,
			usage: msg.usage ?? null,
			stop_reason: msg.stopReason ?? "",
			tool_calls: toolCalls,
			output_text: truncate(textParts.join("\n")),
		});
	});

	// ------------------------------------------------------------------
	// Tool execution lifecycle (creates tool spans)
	// ------------------------------------------------------------------

	pi.on("tool_execution_start", (event) => {
		post("tool_execution_start", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			args: truncate(event.args),
		});
	});

	pi.on("tool_execution_end", (event) => {
		post("tool_execution_end", sessionId, {
			tool_call_id: event.toolCallId,
			tool_name: event.toolName,
			result: truncate(event.result),
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
