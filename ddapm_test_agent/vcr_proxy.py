import hashlib
import json
import os
import re
from urllib.parse import urljoin

from aiohttp.web import Request
from aiohttp.web import Response
import requests
import vcr

def url_path_join(base_url: str, path: str) -> str:
    """Join a base URL with a path, handling slashes automatically."""
    return urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))


PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "azure-openai": "https://dd.openai.azure.com/",
    "deepseek": "https://api.deepseek.com/",
    "anthropic": "https://api.anthropic.com/",
    "datadog": "https://api.datadoghq.com/",
    "genai": "https://generativelanguage.googleapis.com/"
}

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


def get_vcr(subdirectory: str, vcr_cassettes_directory: str) -> vcr.VCR:
    cassette_dir = os.path.join(vcr_cassettes_directory, subdirectory)

    return vcr.VCR(
        cassette_library_dir=cassette_dir,
        record_mode="once",
        match_on=["path", "method"],
        filter_headers=[
            "authorization",
            "OpenAI-Organization",
            "api-key",
            "x-api-key",
            "dd-api-key",
            "dd-application-key",
        ],
    )


def generate_cassette_name(path: str, method: str, body: bytes) -> str:
    decoded_body = normalize_multipart_body(body) if body else ""
    try:
        parsed_body = json.loads(decoded_body) if decoded_body else {}
    except json.JSONDecodeError:
        parsed_body = decoded_body

    request_details = f"{path}:{method}:{json.dumps(parsed_body, sort_keys=True)}"
    hash_object = hashlib.sha256(request_details.encode())
    hash_hex = hash_object.hexdigest()[:8]
    safe_path = "".join(c if c.isalnum() or c in ".-" else "_" for c in path)
    return f"{safe_path}_{method.lower()}_{hash_hex}"


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
    cassette_name = generate_cassette_name(path, request.method, body_bytes)
    with get_vcr(provider, vcr_cassettes_directory).use_cassette(f"{cassette_name}.yaml"):
        oai_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=body_bytes,
            cookies=dict(request.cookies),
            allow_redirects=False,
            stream=True,
        )

    # Extract content type without charset
    content_type = oai_response.headers.get("content-type", "")
    if ";" in content_type:
        content_type = content_type.split(";")[0].strip()

    response = Response(
        body=oai_response.content,
        status=oai_response.status_code,
        content_type=content_type,
    )

    for key, value in oai_response.headers.items():
        if key.lower() not in (
            "content-length",
            "transfer-encoding",
            "content-encoding",
            "connection",
        ):
            response.headers[key] = value

    return response
