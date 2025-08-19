import hashlib
import hmac
import json
import logging
import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import quote
from urllib.parse import urljoin
from urllib.parse import urlparse

from aiohttp.web import Request
from aiohttp.web import Response
import requests
import vcr


logger = logging.getLogger(__name__)


AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


def url_path_join(base_url: str, path: str) -> str:
    """Join a base URL with a path, handling slashes automatically."""
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


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


def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    """Generate AWS signing key"""
    k_date = sign(f"AWS4{secret_key}".encode("utf-8"), date)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    return sign(k_service, "aws4_request")


def create_canonical_request(
    method: str, path: str, query_params: str, headers: Dict[str, Any], signed_headers: List[str], payload_hash: str
) -> str:
    """Create canonical request for AWS signature calculation"""
    # Encode path segments (colons become %3A for model IDs like anthropic.claude-3-5-sonnet-20240620-v1:0)
    canonical_uri = path if path else "/"
    if canonical_uri != "/":
        segments = canonical_uri.split("/")
        encoded_segments = [quote(segment, safe="") if segment else "" for segment in segments]
        canonical_uri = "/".join(encoded_segments)

    # Encode query parameters
    canonical_query = ""
    if query_params:
        parsed_query = parse_qs(query_params, keep_blank_values=True)
        sorted_params = [
            f"{quote(str(key), safe='')}={quote(str(value), safe='')}"
            for key in sorted(parsed_query.keys())
            for value in sorted(parsed_query[key])
        ]
        canonical_query = "&".join(sorted_params)

    # Format headers
    headers_lower = {k.lower(): v for k, v in headers.items()}
    canonical_headers = "".join(
        f"{header.lower()}:{' '.join(str(headers_lower.get(header.lower(), '')).strip().split())}\n"
        for header in sorted(signed_headers)
    )
    signed_headers_str = ";".join(h.lower() for h in sorted(signed_headers))

    return f"{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers_str}\n{payload_hash}"


def get_vcr(subdirectory: str, vcr_cassettes_directory: str) -> vcr.VCR:
    cassette_dir = os.path.join(vcr_cassettes_directory, subdirectory)

    return vcr.VCR(
        cassette_library_dir=cassette_dir,
        record_mode="once",
        match_on=["path", "method"],
        filter_headers=CASSETTE_FILTER_HEADERS,
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


async def proxy_request(request: Request, vcr_cassettes_directory: str) -> Response:
    path = request.match_info["path"]
    if request.query_string:
        path = path + "?" + request.query_string

    parts = path.split("/", 1)
    if len(parts) != 2:
        return Response(body="Invalid path format. Expected /{provider}/...", status=400)

    provider, remaining_path = parts
    if provider not in PROVIDER_BASE_URLS:
        return Response(body=f"Unsupported provider: {provider}", status=400)

    target_url = url_path_join(PROVIDER_BASE_URLS[provider], remaining_path)

    headers = {key: value for key, value in request.headers.items() if key != "Host"}

    body_bytes = await request.read()

    vcr_cassette_prefix = request.pop("vcr_cassette_prefix", None)
    cassette_name = generate_cassette_name(path, request.method, body_bytes, vcr_cassette_prefix)

    if provider == "bedrock-runtime" and not os.path.exists(os.path.join(vcr_cassettes_directory, provider, cassette_name)):
        # Extract AWS headers needed for signature recalculation
        auth_header = request.headers.get("Authorization", "")
        x_amz_security_token = request.headers.get("x-amz-security-token", "")
        x_amz_date = request.headers.get("x-amz-date", "")
        
        if not auth_header.startswith("AWS4-HMAC-SHA256"):
            return Response(body="Missing AWS4-HMAC-SHA256 authorization header", status=400)
        if not x_amz_security_token or not x_amz_date:
            return Response(body="Missing required AWS headers", status=400)
        
        # Parse authorization components and setup headers for real AWS endpoint
        auth_parts = parse_authorization_header(auth_header)
        aws_access_key = auth_parts.get("Credential", "").split("/")[0]
        signed_headers = auth_parts.get("SignedHeaders", "").split(";")
        parsed_url = urlparse(target_url)
        headers = dict(request.headers)
        headers["Host"] = parsed_url.netloc
        
        # Regenerate AWS signature for the real bedrock endpoint (proxy signature was for localhost)
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if not secret_key:
            return Response(body="AWS_SECRET_ACCESS_KEY environment variable not set", status=500)
            
        date = x_amz_date[:8]  # Extract date in YYYYMMDD format
        # Create canonical request with proper URL encoding (colons -> %3A for model IDs)
        canonical_request = create_canonical_request(
            request.method, parsed_url.path, parsed_url.query, headers, 
            signed_headers, headers.get("x-amz-content-sha256", "")
        )
        # Build string to sign and compute new signature
        string_to_sign = f"AWS4-HMAC-SHA256\n{x_amz_date}\n{date}/{AWS_REGION}/bedrock/aws4_request\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        signing_key = get_signing_key(secret_key, date, AWS_REGION, "bedrock")
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        
        # Replace authorization header with new signature for AWS endpoint
        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={aws_access_key}/{date}/{AWS_REGION}/bedrock/aws4_request,SignedHeaders={';'.join(signed_headers)},Signature={signature}"

    with get_vcr(provider, vcr_cassettes_directory).use_cassette(f"{cassette_name}.yaml"):
        provider_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=body_bytes,
            cookies=dict(request.cookies),
            allow_redirects=False,
            stream=True,
        )

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
