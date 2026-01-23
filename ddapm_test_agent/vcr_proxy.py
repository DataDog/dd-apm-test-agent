import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import TypedDict
from typing import cast
from urllib.parse import urljoin

from aiohttp.web import Request
from aiohttp.web import Response
import requests
from requests_aws4auth import AWS4Auth


logger = logging.getLogger(__name__)


class CassetteDataRequest(TypedDict):
    """Represents the request portion of a cassette."""

    method: str
    url: str
    headers: Dict[str, str]
    body: str


class CassetteDataResponse(TypedDict):
    """Represents the response portion of a cassette."""

    status: Dict[str, Any]  # {"code": int, "message": str}
    headers: Dict[str, str]
    body: str


class CassetteData(TypedDict):
    """Represents a VCR cassette with request and response data."""

    request: CassetteDataRequest
    response: CassetteDataResponse


#  Used for AWS signature recalculation for aws services initial proxying
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


AWS_SERVICES = {
    "bedrock-runtime": "bedrock",
}


PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "azure-openai": "https://dd.openai.azure.com/",
    "deepseek": "https://api.deepseek.com/",
    "anthropic": "https://api.anthropic.com/",
    "datadog": "https://api.datadoghq.com/",
    "genai": "https://generativelanguage.googleapis.com/",
    "bedrock-runtime": f"https://bedrock-runtime.{AWS_REGION}.amazonaws.com",
}

CASSETTE_FILTER_HEADERS = [
    "authorization",
    "OpenAI-Organization",
    "api-key",
    "x-api-key",
    "dd-api-key",
    "dd-application-key",
    "x-goog-api-key",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-user-agent",
    "amz-sdk-invocation-id",
    "amz-sdk-request",
]

NORMALIZERS = [
    (
        r"--form-data-boundary-[^\r\n]+",
        "--form-data-boundary-normalized",
    ),  # openai file types
    (
        r"------formdata-undici-[^\r\n]+",
        "--form-data-boundary-normalized",
    ),  # openai file types for undici (node.js)
]


def _url_path_join(base_url: str, path: str) -> str:
    """Join a base URL with a path, handling slashes automatically."""
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _file_safe_string(s: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in s)


def _get_custom_vcr_providers(vcr_provider_map: str) -> Dict[str, str]:
    return dict(
        [
            vcr_provider_map.strip().split("=", 1)
            for vcr_provider_map in vcr_provider_map.split(",")
            if vcr_provider_map.strip()
        ]
    )


def _normalize_multipart_body(body: bytes) -> str:
    if not body:
        return ""

    try:
        body_str = body.decode("utf-8")

        for pattern, replacement in NORMALIZERS:
            body_str = re.sub(pattern, replacement, body_str)

        return body_str
    except UnicodeDecodeError:
        try:
            body_str = body.decode("latin-1")

            for pattern, replacement in NORMALIZERS:
                body_str = re.sub(pattern, replacement, body_str)

            return body_str
        except Exception:
            hex_digest = hashlib.sha256(body).hexdigest()[:8]
            return f"[binary_data_{hex_digest}]"


def _decode_body(body: bytes) -> str:
    """Decode body (request or response), handling binary data gracefully."""
    if not body:
        return ""

    # Check for null bytes - strong indicator of binary data (e.g., event streams, protobuf)
    if b"\x00" in body:
        return "base64:" + base64.b64encode(body).decode("ascii")

    try:
        # Try UTF-8 decode - if successful, it's text
        return body.decode("utf-8")
    except UnicodeDecodeError:
        # If UTF-8 fails, treat as binary
        return "base64:" + base64.b64encode(body).decode("ascii")


def _encode_body(body: str) -> bytes:
    """Convert cassette body string back to bytes, handling base64-encoded data."""
    if not body:
        return b""

    # Check for base64 marker first (for binary data that was base64-encoded)
    if body.startswith("base64:"):
        return base64.b64decode(body[7:])

    try:
        # Try to encode as UTF-8 (most common case)
        return body.encode("utf-8")
    except UnicodeEncodeError:
        # If all else fails, encode as latin-1
        return body.encode("latin-1")


def _parse_authorization_header(auth_header: str) -> Dict[str, str]:
    """Parse AWS Authorization header to extract components"""
    if not auth_header.startswith("AWS4-HMAC-SHA256 "):
        return {}

    auth_parts = auth_header[len("AWS4-HMAC-SHA256 ") :].split(",")
    parsed = {}

    for part in auth_parts:
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()

    return parsed


def _generate_cassette_name(path: str, method: str, body: bytes, vcr_cassette_prefix: Optional[str]) -> str:
    decoded_body = _normalize_multipart_body(body) if body else ""
    try:
        parsed_body = json.loads(decoded_body) if decoded_body else {}
    except json.JSONDecodeError:
        parsed_body = decoded_body

    request_details = f"{path}:{method}:{json.dumps(parsed_body, sort_keys=True)}"
    hash_object = hashlib.sha256(request_details.encode())
    hash_hex = hash_object.hexdigest()[:8]
    safe_path = _file_safe_string(path)

    safe_vcr_cassette_prefix = _file_safe_string(vcr_cassette_prefix) if vcr_cassette_prefix else None

    return (
        f"{safe_vcr_cassette_prefix}_{safe_path}_{method.lower()}_{hash_hex}"
        if safe_vcr_cassette_prefix
        else f"{safe_path}_{method.lower()}_{hash_hex}"
    )


def _filter_headers(headers: Dict[str, Any], ignore_headers: List[str]) -> Dict[str, str]:
    """Filter headers and normalize their values."""
    return {key: value for key, value in headers.items() if key.lower() not in ignore_headers}


def _write_cassette_file(
    cassette_file_path: str,
    request_kwargs: Dict[str, Any],
    response: requests.Response,
    vcr_ignore_headers: str,
) -> None:
    """Write cassette data to a JSON file."""
    logger.info(f"Writing cassette file to {cassette_file_path}")

    cassette_dir = os.path.dirname(cassette_file_path)
    os.makedirs(cassette_dir, exist_ok=True)

    ignore_headers_list = [
        header.lower() for header in CASSETTE_FILTER_HEADERS + vcr_ignore_headers.split(",") if header
    ]

    cassette = CassetteData(
        request=CassetteDataRequest(
            method=request_kwargs["method"],
            url=request_kwargs["url"],
            headers=_filter_headers(request_kwargs["headers"], ignore_headers_list),
            body=_decode_body(request_kwargs["data"]) if request_kwargs["data"] else "",
        ),
        response=CassetteDataResponse(
            status={
                "code": response.status_code,
                "message": response.reason or "",
            },
            headers=_filter_headers(dict(response.headers), ignore_headers_list),
            body=_decode_body(response.content) if response.content else "",
        ),
    )

    with open(cassette_file_path, "w") as f:
        json.dump(cassette, f, indent=2)


def _write_response_headers(response: Response, headers: Mapping[str, str]) -> None:
    skip_headers = {"content-length", "transfer-encoding", "content-encoding", "connection"}
    for key, value in headers.items():
        if key.lower() not in skip_headers:
            response.headers[key] = value


async def _request(
    cassette_file_path: str, cassette_exists: bool, request_kwargs: Dict[str, Any], vcr_ignore_headers: str
) -> Response:
    """Load a cassette from file if it exists, otherwise make a request and save the response."""
    logger.info(f"Making a request to {request_kwargs['url']} with method {request_kwargs['method']}")

    cassette: Optional[CassetteData] = None

    if cassette_exists:
        logger.info(f"Cassette file exists at {cassette_file_path}")

        with open(cassette_file_path, "r") as f:
            cassette = cast(CassetteData, json.load(f))

        response_body = _encode_body(cassette["response"]["body"])
        response = Response(
            body=response_body,
            status=cassette["response"]["status"]["code"],
        )

        response_headers = cassette["response"]["headers"]
    else:
        logger.info(f"Cassette file does not exist at {cassette_file_path}, making a request to the provider")
        provider_response = await asyncio.to_thread(lambda: requests.request(**request_kwargs))

        _write_cassette_file(cassette_file_path, request_kwargs, provider_response, vcr_ignore_headers)

        response = Response(body=provider_response.content, status=provider_response.status_code)
        response_headers = dict(provider_response.headers)

    _write_response_headers(response, response_headers)

    return response


async def proxy_request(
    request: Request, vcr_cassettes_directory: str, vcr_ci_mode: bool, vcr_provider_map: str, vcr_ignore_headers: str
) -> Response:
    provider_base_urls = PROVIDER_BASE_URLS.copy()
    provider_base_urls.update(_get_custom_vcr_providers(vcr_provider_map))

    path = request.match_info["path"]
    if request.query_string:
        path = path + "?" + request.query_string

    parts = path.split("/", 1)
    if len(parts) != 2:
        return Response(body="Invalid path format. Expected /{provider}/...", status=400)

    provider, remaining_path = parts
    if provider not in provider_base_urls:
        return Response(body=f"Unsupported provider: {provider}", status=400)

    body_bytes = await request.read()

    vcr_cassette_prefix = request.pop("vcr_cassette_prefix", None)
    cassette_name = _generate_cassette_name(path, request.method, body_bytes, vcr_cassette_prefix)
    cassette_file_name = f"{cassette_name}.json"
    cassette_file_path = os.path.join(vcr_cassettes_directory, provider, cassette_file_name)
    cassette_exists = os.path.exists(cassette_file_path)

    if vcr_ci_mode and not cassette_exists:
        return Response(
            body=f"Cassette {cassette_name} not found while running in CI mode. Please generate the cassette locally and commit it.",
            status=500,
        )

    target_url = _url_path_join(provider_base_urls[provider], remaining_path)
    skip_headers = {"host", "transfer-encoding"}
    headers = {key: value for key, value in request.headers.items() if not (key.lower() in skip_headers)}

    request_kwargs: Dict[str, Any] = {
        "method": request.method,
        "url": target_url,
        "headers": headers,
        "data": body_bytes,
        "cookies": dict(request.cookies),
        "allow_redirects": False,
        "stream": True,
    }

    if provider in AWS_SERVICES and not cassette_exists:
        if not AWS_SECRET_ACCESS_KEY:
            return Response(
                body="AWS_SECRET_ACCESS_KEY environment variable not set for aws signature recalculation",
                status=400,
            )

        auth_header = request.headers.get("Authorization", "")
        auth_parts = _parse_authorization_header(auth_header)
        aws_access_key = auth_parts.get("Credential", "").split("/")[0]

        auth = AWS4Auth(aws_access_key, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_SERVICES[provider])
        request_kwargs["auth"] = auth

    return await _request(cassette_file_path, cassette_exists, request_kwargs, vcr_ignore_headers)
