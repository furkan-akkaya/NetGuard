"""Request guard: defences for an API that usually listens on localhost (THREAT_MODEL.md).

A service on 127.0.0.1 is reachable from every web page the user opens, through
the user's own browser. Three checks run before any route:

* **Host allowlist (DNS rebinding).** A malicious site can re-resolve its own
  domain to 127.0.0.1; the browser then treats the API as same-origin with the
  attacker's page. Such requests carry the attacker's name in ``Host``, so only
  loopback names and explicitly allowed hosts are accepted.
* **Cross-origin writes (CSRF).** Browsers send some cross-site requests
  without a CORS preflight ("simple requests", e.g. ``Content-Type:
  text/plain``). A state-changing request whose ``Origin`` is not exactly this
  server (scheme, host *and* port: another port on localhost is another
  site's service) or an explicitly allowed origin is refused, as are ``null``
  and malformed origins. Requests without ``Origin`` (curl, scripts) are
  unaffected. Behind a TLS proxy the browser's origin (``https://name``)
  differs from what NetGuard sees (``http``), so it must be allowed by name.
* **Body size.** Everything except the capture upload (which streams with its
  own cap) is limited to ``MAX_BODY`` bytes, counted while reading, so a
  chunked request cannot bypass a ``Content-Length`` check.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from starlette.exceptions import HTTPException

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_BODY = 1024 * 1024
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
DEFAULT_PORTS = {"http": 80, "https": 443}
Origin = tuple[str, str, int]  # scheme, host, port


def _host_only(value: str) -> str:
    """'Example.org:8000' -> 'example.org'; '[::1]:8000' -> '[::1]'."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[: value.find("]") + 1]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def parse_origin(value: str) -> Origin | None:
    """'https://Name:443' -> ('https', 'name', 443); None for null, paths or anything malformed."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not parts.hostname or parts.username or parts.password:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    return scheme, parts.hostname.lower(), port or DEFAULT_PORTS[scheme]


def _request_origin(scheme: str, host_header: str) -> Origin | None:
    return parse_origin(f"{scheme}://{host_header}") if host_header else None


class RequestGuard:
    def __init__(
        self,
        app: App,
        allowed_hosts: Iterable[str],
        streamed_paths: Iterable[str] = (),
        allowed_origins: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.allowed = LOOPBACK_HOSTS | {_host_only(h) for h in allowed_hosts if h}
        self.streamed = tuple(streamed_paths)
        self.origins = {o for o in (parse_origin(v) for v in allowed_origins) if o is not None}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        host = _host_only(headers.get("host", ""))
        if host not in self.allowed:
            await _reject(send, 421, "unknown host name (allow it with --allowed-host if this is intended)")
            return
        method = scope["method"]
        origin = headers.get("origin")
        if method in UNSAFE_METHODS and origin is not None:
            claimed = parse_origin(origin)
            own = _request_origin(scope.get("scheme", "http"), headers.get("host", ""))
            if claimed is None or (claimed != own and claimed not in self.origins):
                await _reject(send, 403, "cross-origin request refused")
                return
        path = scope.get("path", "")
        if any(path == p or path.startswith(p + "?") for p in self.streamed) or method not in UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return
        declared = headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY:
            await _reject(send, 413, f"request body larger than {MAX_BODY} bytes")
            return
        seen = 0

        async def limited() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_BODY:
                    # Raised inside the app's body read, so the framework turns it into a 413.
                    raise HTTPException(status_code=413, detail=f"request body larger than {MAX_BODY} bytes")
            return message

        await self.app(scope, limited, send)


async def _reject(send: Send, status: int, detail: str) -> None:
    body = ('{"detail": "' + detail.replace('"', "'") + '"}').encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
