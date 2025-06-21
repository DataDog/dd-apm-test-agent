import requests
import vcr
import hashlib
import os
import json
import re

from aiohttp import web
from aiohttp.web import Request, Response

PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "azure-openai": "https://dd.openai.azure.com/",
    "deepseek": "https://api.deepseek.com/",
}

NORMALIZERS = [
    (
        r"--form-data-boundary-[^\r\n]+",
        "--form-data-boundary-normalized",
    ),  # openai file types
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


def get_vcr(subdirectory: str):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return vcr.VCR(
        cassette_library_dir=os.path.join(current_dir, "snapshot-server-cassettes", subdirectory),
        record_mode="once",
        match_on=["path", "method"],
        filter_headers=["authorization", "OpenAI-Organization", "api-key", "x-api-key"],
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

def forward_request(request: Request) -> Response:
    path = request.match_info["path"]

    parts = path.split("/", 1)
    if len(parts) != 2:
        return Response("Invalid path format. Expected /{provider}/...", status=400)

    provider, remaining_path = parts
    if provider not in PROVIDER_BASE_URLS:
        return Response(f"Unsupported provider: {provider}", status=400)

    target_url = f"{PROVIDER_BASE_URLS[provider]}/{remaining_path}"

    headers = {key: value for key, value in request.headers if key != "Host"}

    cassette_name = generate_cassette_name(path, request.method, request.get_data())
    with get_vcr(provider).use_cassette(f"{cassette_name}.yaml"):
        oai_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
        )

    response = Response(
        oai_response.iter_content(chunk_size=10 * 1024),
        status=oai_response.status_code,
        content_type=oai_response.headers.get("content-type"),
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