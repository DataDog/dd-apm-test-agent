from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Tuple

from aiohttp.web import Response
from aiohttp.web_request import Request


Handler = Callable[[Request], Awaitable[Response]]


def parse_csv(s: str) -> List[str]:
    """Return the values of a csv string."""
    return [s.strip() for s in s.split(",") if s.strip() != ""]


def parse_map(s: str) -> Dict[str, str]:
    """Return the values of a csv-style map string 'a:b,b:c'."""
    return dict([s.strip().split(":", 1) for s in s.split(",") if s.strip()])


def session_token(request: Request) -> Optional[str]:
    """Extract session token from headers or query params."""
    token: Optional[str]
    if "X-Datadog-Test-Session-Token" in request.headers:
        token = request.headers["X-Datadog-Test-Session-Token"]
    elif "test_session_token" in request.url.query:
        token = request.url.query.get("test_session_token")
    else:
        token = None
    return token
