import asyncio
import hashlib
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import Optional
from urllib.parse import urljoin

from aiohttp.web import Request
from aiohttp.web import Response
import requests
from requests_aws4auth import AWS4Auth
import vcr


logger = logging.getLogger(__name__)


#  Used for AWS signature recalculation for aws services initial proxying
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


def url_path_join(base_url: str, path: str) -> str:
    """Join a base URL with a path, handling slashes automatically."""
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


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


def _file_safe_string(s: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in s)


def get_custom_vcr_providers(vcr_provider_map: str) -> Dict[str, str]:
    return dict(
        [
            vcr_provider_map.strip().split("=", 1)
            for vcr_provider_map in vcr_provider_map.split(",")
            if vcr_provider_map.strip()
        ]
    )


def normalize_multipart_body(body: bytes) -> str:
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


def parse_authorization_header(auth_header: str) -> Dict[str, str]:
    """Parse AWS Authorization header to extract components"""
    if not auth_header.startswith("AWS4-HMAC-SHA256 "):
        return {}

    auth_parts = auth_header[len("AWS4-HMAC-SHA256 ") :].split(",")
    parsed = {}

    for part in auth_parts:
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()

    return parsed


def get_vcr(subdirectory: str, vcr_cassettes_directory: str, vcr_ignore_headers: str) -> vcr.VCR:
    cassette_dir = os.path.join(vcr_cassettes_directory, subdirectory)
    extra_ignore_headers = vcr_ignore_headers.split(",")

    return vcr.VCR(
        cassette_library_dir=cassette_dir,
        record_mode="once",
        match_on=["path", "method"],
        filter_headers=CASSETTE_FILTER_HEADERS + extra_ignore_headers,
    )


def generate_cassette_name(path: str, method: str, body: bytes, vcr_cassette_prefix: Optional[str]) -> str:
    decoded_body = normalize_multipart_body(body) if body else ""
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


async def proxy_request(
    request: Request, vcr_cassettes_directory: str, vcr_ci_mode: bool, vcr_provider_map: str, vcr_ignore_headers: str
) -> Response:
    provider_base_urls = PROVIDER_BASE_URLS.copy()
    provider_base_urls.update(get_custom_vcr_providers(vcr_provider_map))

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
    cassette_name = generate_cassette_name(path, request.method, body_bytes, vcr_cassette_prefix)
    cassette_file_name = f"{cassette_name}.yaml"
    cassette_file_path = os.path.join(vcr_cassettes_directory, provider, cassette_file_name)
    cassette_exists = os.path.exists(cassette_file_path)

    if vcr_ci_mode and not cassette_exists:
        return Response(
            body=f"Cassette {cassette_file_name} not found while running in CI mode. Please generate the cassette locally and commit it.",
            status=500,
        )

    target_url = url_path_join(provider_base_urls[provider], remaining_path)
    headers = {key: value for key, value in request.headers.items() if key != "Host"}

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
        auth_parts = parse_authorization_header(auth_header)
        aws_access_key = auth_parts.get("Credential", "").split("/")[0]

        auth = AWS4Auth(aws_access_key, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_SERVICES[provider])
        request_kwargs["auth"] = auth

    def _make_request():
        with get_vcr(provider, vcr_cassettes_directory, vcr_ignore_headers).use_cassette(cassette_file_name):
            return requests.request(**request_kwargs)

    provider_response = await asyncio.to_thread(_make_request)

    # Extract content type without charset
    content_type = provider_response.headers.get("content-type", "")
    if ";" in content_type:
        content_type = content_type.split(";")[0].strip()

    response = Response(
        body=provider_response.content,
        status=provider_response.status_code,
        content_type=content_type,
    )

    for key, value in provider_response.headers.items():
        if key.lower() not in (
            "content-length",
            "transfer-encoding",
            "content-encoding",
            "connection",
        ):
            response.headers[key] = value

    return response
