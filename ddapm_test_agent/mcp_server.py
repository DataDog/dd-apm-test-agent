import inspect
import json
import logging
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import TYPE_CHECKING
from typing import Tuple
from typing import Union
from typing import get_args
from typing import get_origin

from aiohttp import web
import docstring_parser

from . import _get_version
from .llmobs_event_platform import LLMObsEventPlatformAPI
from .llmobs_event_platform import apply_filters
from .llmobs_event_platform import parse_filter_query


if TYPE_CHECKING:
    from .agent import Agent


log = logging.getLogger(__name__)

TYPE_MAP = {
    "str": "string",
    "int": "number",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "set": "array",
    "tuple": "array",
}


def _quotable(value: Any) -> str:
    return f'"{value}"'


def _type_to_json_schema(annotation: Any) -> Dict[str, Any]:
    if annotation is type(None):
        return {"type": "null"}

    origin = get_origin(annotation)

    if origin is Union:
        non_none_args = [arg for arg in get_args(annotation) if arg is not type(None)]
        return _type_to_json_schema(non_none_args[0]) if non_none_args else {"type": "null"}

    if origin is Literal:
        enum_values = list(get_args(annotation))
        json_type = TYPE_MAP.get(type(enum_values[0]).__name__, "string") if enum_values else "string"
        return {"type": json_type, "enum": enum_values}

    if origin in (list, set):
        schema: Dict[str, Any] = {"type": "array"}
        if origin is set:
            schema["uniqueItems"] = True
        args = get_args(annotation)
        if args:
            schema["items"] = _type_to_json_schema(args[0])
        return schema

    if origin is tuple:
        args = get_args(annotation)
        if args:
            return {
                "type": "array",
                "items": _type_to_json_schema(args[0]),
                "minItems": len(args),
                "maxItems": len(args),
            }
        return {"type": "array"}

    if hasattr(annotation, "__name__"):
        return {"type": TYPE_MAP.get(annotation.__name__, annotation.__name__)}

    return {"type": "string"}


def build_query_str(
    free_text_search: Optional[str] = None,
    span_kind: Optional[List[Literal["llm", "tool", "retrieval", "embedding", "agent", "task", "workflow"]]] = None,
    status: Optional[Literal["ok", "error"]] = None,
    model_provider: Optional[List[str]] = None,
    model_name: Optional[List[str]] = None,
    span_name: Optional[List[str]] = None,
    duration_range: Optional[Tuple[str, str]] = None,
    input_tokens_range: Optional[Tuple[int, int]] = None,
    output_tokens_range: Optional[Tuple[int, int]] = None,
    total_tokens_range: Optional[Tuple[int, int]] = None,
    num_errors_range: Optional[Tuple[int, int]] = None,
    num_llm_calls_range: Optional[Tuple[int, int]] = None,
    num_tool_calls_range: Optional[Tuple[int, int]] = None,
    num_retrieval_calls_range: Optional[Tuple[int, int]] = None,
) -> str:
    query = []

    if span_kind:
        query.append(f"@meta.span.kind:({' OR '.join(span_kind)})")

    if status:
        query.append(f"@status:{status}")

    if model_provider:
        query.append(f"@meta.model_provider:({' OR '.join([_quotable(provider) for provider in model_provider])})")

    if model_name:
        query.append(f"@meta.model_name:({' OR '.join([_quotable(name) for name in model_name])})")

    if span_name:
        query.append(f"@name:({' OR '.join([_quotable(name) for name in span_name])})")

    if duration_range:
        query.append(f"@duration:[{duration_range[0]} TO {duration_range[1]}]")

    if input_tokens_range:
        query.append(f"@trace.input_tokens:[{input_tokens_range[0]} TO {input_tokens_range[1]}]")

    if output_tokens_range:
        query.append(f"@trace.output_tokens:[{output_tokens_range[0]} TO {output_tokens_range[1]}]")

    if total_tokens_range:
        query.append(f"@trace.output_tokens:[{total_tokens_range[0]} TO {total_tokens_range[1]}]")

    if num_errors_range:
        query.append(f"@trace.number_of_errors:[{num_errors_range[0]} TO {num_errors_range[1]}]")

    if num_llm_calls_range:
        query.append(f"@trace.llm_calls:[{num_llm_calls_range[0]} TO {num_llm_calls_range[1]}]")

    if num_tool_calls_range:
        query.append(f"@trace.tool_calls:[{num_tool_calls_range[0]} TO {num_tool_calls_range[1]}]")

    if num_retrieval_calls_range:
        query.append(f"@trace.retrieval_calls:[{num_retrieval_calls_range[0]} TO {num_retrieval_calls_range[1]}]")

    if free_text_search:
        query.append(free_text_search)

    return " ".join(query)


class _Tool:
    def __init__(self, func: Callable[..., Any]):
        self.func = func
        self.is_async = inspect.iscoroutinefunction(func)
        self.name = func.__name__

        description = func.__doc__
        if not description:
            raise ValueError(f"Function {self.name} must have a docstring")
        self.description = description

        parameters = inspect.signature(func).parameters
        doc = docstring_parser.parse(description)

        arguments = {}
        required = []
        for name, param in parameters.items():
            if name == "self":
                continue
            argument = {}

            if param.annotation and param.annotation != inspect.Parameter.empty:
                argument = _type_to_json_schema(param.annotation)

            if param.default != inspect.Parameter.empty:
                # Only include default if it's not None
                if param.default is not None:
                    argument["default"] = param.default
            else:
                required.append(name)

            doc_param = next((p for p in doc.params if p.arg_name == name), None)
            if not doc_param or not doc_param.description:
                raise ValueError(f"Function {self.name} must have a description for parameter {name}")
            argument["description"] = doc_param.description

            arguments[name] = argument

        self.arguments = arguments
        self.required = required

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.arguments,
                "required": self.required,
            },
        }

    def __str__(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def call(self, **kwargs: Any) -> Any:
        return self.func(**kwargs)

    async def call_async(self, **kwargs: Any) -> Any:
        return await self.func(**kwargs)


class MCPServer:
    def __init__(self, agent: "Agent", llmobs_event_platform_api: "LLMObsEventPlatformAPI"):
        self.agent = agent
        self.llmobs_event_platform_api = llmobs_event_platform_api
        self.tools: List[_Tool] = [
            _Tool(self.get_llmobs_span_events),
        ]

    async def handle_request(self, request: web.Request) -> web.Response:
        body: Dict[str, Any] = await request.json()
        method: str = body["method"]
        request_id: str | None = body.get("id")

        log.info(f"Handling MCP request for {method}")

        if method == "initialize":
            return self.initialize(request_id)
        elif method == "tools/list":
            return self.tools_list(request_id)
        elif method == "tools/call":
            return await self.call_tool(request_id, body)
        elif method == "notifications/initialized":
            return web.Response(status=204)
        else:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                },
                status=400,
            )

    def initialize(self, request_id: str | None) -> web.Response:
        return web.json_response(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "ddapm-test-agent",
                        "version": _get_version(),
                    },
                },
            }
        )

    def tools_list(self, request_id: str | None) -> web.Response:
        return web.json_response(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [t.to_dict() for t in self.tools],
                },
            }
        )

    async def call_tool(self, request_id: str | None, tool_call_request: Dict[str, Any]) -> web.Response:
        tool_params: Dict[str, Any] = tool_call_request["params"]

        tool_name: str = tool_params["name"]
        tool_arguments: Dict[str, Any] = tool_params["arguments"]

        tool = next((t for t in self.tools if t.name == tool_name), None)
        if not tool:
            return web.HTTPBadRequest(text=f"Unknown tool: {tool_name}")

        result = await tool.call_async(**tool_arguments) if tool.is_async else tool.call(**tool_arguments)
        return web.json_response(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2),
                        }
                    ]
                },
            }
        )

    def get_llmobs_span_events(
        self,
        num_events: Optional[int] = 100,
        free_text_search: Optional[str] = None,
        span_kind: Optional[List[Literal["llm", "tool", "retrieval", "embedding", "agent", "task", "workflow"]]] = None,
        status: Optional[Literal["ok", "error"]] = None,
        model_provider: Optional[List[str]] = None,
        model_name: Optional[List[str]] = None,
        span_name: Optional[List[str]] = None,
        duration_range: Optional[Tuple[str, str]] = None,
        input_tokens_range: Optional[Tuple[int, int]] = None,
        output_tokens_range: Optional[Tuple[int, int]] = None,
        total_tokens_range: Optional[Tuple[int, int]] = None,
        num_errors_range: Optional[Tuple[int, int]] = None,
        num_llm_calls_range: Optional[Tuple[int, int]] = None,
        num_tool_calls_range: Optional[Tuple[int, int]] = None,
        num_retrieval_calls_range: Optional[Tuple[int, int]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all LLMObs span events from the test agent.

        Args:
            num_events: The number of span events to return
            free_text_search: The free text search to apply to the input, output, metadata, or tags of the span events.
            span_kind: A list of span kinds to filter by
            status: The status of the span to filter by (ok or error)
            model_provider: A list of model providers to filter by
            model_name: A list of model names to filter by
            span_name: A list of span names to filter by
            duration_range: A range of durations to filter by (with units attached, e.g. 1ns, 1ms, 1s, 20m, 1h, 3d)
            input_tokens_range: A range of input tokens to filter by
            output_tokens_range: A range of output tokens to filter by
            total_tokens_range: A range of total tokens to filter by
            num_errors_range: A range of number of errors to filter by
            num_llm_calls_range: A range of number of LLM calls to filter by
            num_tool_calls_range: A range of number of tool calls to filter by
            num_retrieval_calls_range: A range of number of retrieval calls to filter by
        """
        query_str = build_query_str(
            free_text_search=free_text_search,
            span_kind=span_kind,
            status=status,
            model_provider=model_provider,
            model_name=model_name,
            span_name=span_name,
            duration_range=duration_range,
            input_tokens_range=input_tokens_range,
            output_tokens_range=output_tokens_range,
            total_tokens_range=total_tokens_range,
            num_errors_range=num_errors_range,
            num_llm_calls_range=num_llm_calls_range,
            num_tool_calls_range=num_tool_calls_range,
            num_retrieval_calls_range=num_retrieval_calls_range,
        )

        llmobs_span_events = self.llmobs_event_platform_api.get_llmobs_spans()

        if query_str:
            llmobs_span_events = apply_filters(llmobs_span_events, parse_filter_query(query_str))

        return llmobs_span_events[:num_events]
