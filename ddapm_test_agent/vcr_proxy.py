import asyncio
import base64
from dataclasses import dataclass
from glob import glob
import hashlib
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union
from typing import cast
from urllib.parse import urljoin

from aiohttp.web import Request
from aiohttp.web import Response
import requests
from requests_aws4auth import AWS4Auth
import yaml


logger = logging.getLogger(__name__)


@dataclass
class CassetteDataRequest:
    """Represents the request portion of a cassette."""

    method: str
    url: str
    headers: Dict[str, str]
    body: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CassetteDataRequest":
        """Create from a dictionary."""
        return cls(
            method=data["method"],
            url=data["url"],
            headers=data["headers"],
            body=data["body"],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class CassetteDataResponse:
    """Represents the response portion of a cassette."""

    status: Dict[str, Any]  # {"code": int, "message": str}
    headers: Dict[str, str]
    body: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CassetteDataResponse":
        """Create from a dictionary."""
        return cls(
            status=data["status"],
            headers=data["headers"],
            body=data["body"],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class CassetteData:
    """Represents a VCR cassette with request and response data."""

    request: CassetteDataRequest
    response: CassetteDataResponse

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CassetteData":
        """Create from a dictionary (e.g., loaded from JSON)."""
        return cls(
            request=CassetteDataRequest.from_dict(data["request"]),
            response=CassetteDataResponse.from_dict(data["response"]),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
        }


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


def _convert_vcr_cassette_to_custom_format(
    cassette_file_path: str,
    request_kwargs: Dict[str, Any],
    vcr_ignore_headers: str,
) -> CassetteData:
    """Convert a VCR YAML cassette to our custom JSON format."""
    cassette_file_path_yaml = f"{cassette_file_path}.yaml"
    with open(cassette_file_path_yaml, "r") as f:
        cassette_data = yaml.load(f, Loader=yaml.UnsafeLoader)

    interaction = cast(Dict[str, Any], cassette_data["interactions"][0])

    cassette = _write_cassette_file(cassette_file_path, request_kwargs, interaction["response"], vcr_ignore_headers)

    logger.warning(f"Removing legacy VCR cassette file {cassette_file_path_yaml}.")
    os.remove(cassette_file_path_yaml)

    return cassette


def _normalize_header_value(value: Any) -> str:
    """Normalize header value to a string (handles list values)."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


def _filter_headers(headers: Dict[str, Any], ignore_headers: List[str]) -> Dict[str, str]:
    """Filter headers and normalize their values."""
    return {key: _normalize_header_value(value) for key, value in headers.items() if key.lower() not in ignore_headers}


def _create_cassette_from_requests_response(
    request_kwargs: Dict[str, Any],
    response: requests.Response,
    ignore_headers: List[str],
) -> CassetteData:
    """Create cassette data from a requests.Response object."""
    logger.info(f"Creating cassette data from requests.Response object: {response.content!r}")
    return CassetteData(
        request=CassetteDataRequest(
            method=request_kwargs["method"],
            url=request_kwargs["url"],
            headers=_filter_headers(request_kwargs["headers"], ignore_headers),
            body=_decode_body(request_kwargs["data"]) if request_kwargs["data"] else "",
        ),
        response=CassetteDataResponse(
            status={
                "code": response.status_code,
                "message": response.reason or "",
            },
            headers=_filter_headers(dict(response.headers), ignore_headers),
            body=_decode_body(response.content) if response.content else "",
        ),
    )


def _create_cassette_from_dict(
    request_kwargs: Dict[str, Any],
    response_dict: Dict[str, Any],
    ignore_headers: List[str],
) -> CassetteData:
    """Create cassette data from a dictionary (e.g., from VCR YAML)."""
    body_data = response_dict["body"]["string"]
    if isinstance(body_data, bytes):
        body_str = _decode_body(body_data)
    else:
        body_str = body_data

    return CassetteData(
        request=CassetteDataRequest(
            method=request_kwargs["method"],
            url=request_kwargs["url"],
            headers=_filter_headers(request_kwargs["headers"], ignore_headers),
            body=_decode_body(request_kwargs["data"]) if request_kwargs["data"] else "",
        ),
        response=CassetteDataResponse(
            status={
                "code": response_dict["status"]["code"],
                "message": response_dict["status"]["message"],
            },
            headers=_filter_headers(response_dict["headers"], ignore_headers),
            body=body_str,
        ),
    )


def _write_cassette_file(
    cassette_file_path: str,
    request_kwargs: Dict[str, Any],
    response: Union[requests.Response, Dict[str, Any]],
    vcr_ignore_headers: str,
) -> CassetteData:
    """Write cassette data to a JSON file."""
    cassette_file_path_json = f"{cassette_file_path}.json"
    logger.info(f"Writing cassette file to {cassette_file_path_json}")

    cassette_dir = os.path.dirname(cassette_file_path_json)
    os.makedirs(cassette_dir, exist_ok=True)

    ignore_headers_list = [
        header.lower() for header in CASSETTE_FILTER_HEADERS + vcr_ignore_headers.split(",") if header
    ]

    if isinstance(response, requests.Response):
        cassette = _create_cassette_from_requests_response(request_kwargs, response, ignore_headers_list)
    else:
        # conversion of legacy VCR cassette to JSON format
        cassette = _create_cassette_from_dict(request_kwargs, response, ignore_headers_list)

    with open(cassette_file_path_json, "w") as f:
        json.dump(cassette.to_dict(), f, indent=2)

    return cassette


async def _request(
    cassette_file_path: str, cassette_exists: bool, request_kwargs: Dict[str, Any], vcr_ignore_headers: str
) -> Response:
    """
    Load a cassette from file if it exists, otherwise make a request and save the response.

    If the cassette was created with the VCR package (YAML format), convert it to JSON format.
    """
    logger.info(f"Making a request to {request_kwargs['url']} with method {request_kwargs['method']}")

    cassette: Optional[CassetteData] = None

    if cassette_exists:
        logger.info(f"Cassette file exists at {cassette_file_path}")
        cassette_files = glob(f"{cassette_file_path}.*")
        if not cassette_files:
            raise FileNotFoundError(f"Expected cassette file at {cassette_file_path}.*")

        file_extension = os.path.splitext(cassette_files[0])[1]

        if file_extension == ".yaml":  # TODO(sabrenner): in a breaking change, remove this
            logger.warning(
                "Converting legacy VCR cassette to JSON format. This will not be supported in ddapm-test-agent==2.0.0"
            )
            cassette = _convert_vcr_cassette_to_custom_format(cassette_file_path, request_kwargs, vcr_ignore_headers)
        elif file_extension == ".json":
            cassette_file_path_json = f"{cassette_file_path}.json"
            with open(cassette_file_path_json, "r") as f:
                cassette = CassetteData.from_dict(json.load(f))
        else:
            raise ValueError(f"Unsupported cassette file extension: {file_extension}")
    else:
        logger.info(f"Cassette file does not exist at {cassette_file_path}, making a request to the provider")
        provider_response = await asyncio.to_thread(lambda: requests.request(**request_kwargs))
        cassette = _write_cassette_file(cassette_file_path, request_kwargs, provider_response, vcr_ignore_headers)

    # Build response from cassette data
    response_body_str = cassette.response.body
    response_body = _encode_body(response_body_str) if isinstance(response_body_str, str) else b""

    response = Response(
        body=response_body,
        status=cassette.response.status["code"],
    )

    skip_headers = {"content-length", "transfer-encoding", "content-encoding", "connection"}
    for key, value in cassette.response.headers.items():
        if key.lower() not in skip_headers:
            response.headers[key] = value

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
    cassette_file_path = os.path.join(vcr_cassettes_directory, provider, cassette_name)
    cassette_exists = len(glob(f"{cassette_file_path}.*")) > 0

    if vcr_ci_mode and not cassette_exists:
        return Response(
            body=f"Cassette {cassette_name} not found while running in CI mode. Please generate the cassette locally and commit it.",
            status=500,
        )

    target_url = _url_path_join(provider_base_urls[provider], remaining_path)
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
        auth_parts = _parse_authorization_header(auth_header)
        aws_access_key = auth_parts.get("Credential", "").split("/")[0]

        auth = AWS4Auth(aws_access_key, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_SERVICES[provider])
        request_kwargs["auth"] = auth

    return await _request(cassette_file_path, cassette_exists, request_kwargs, vcr_ignore_headers)
