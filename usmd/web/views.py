"""Django views for the USMD-RDSH web dashboard.

Authentication uses simple username/password stored in Django settings
(sourced from NodeConfig.web_username / web_password).  No database is
required: session state is stored in a signed cookie.

Remote node data is fetched via the NCP REQUEST_SNAPSHOT command (ID 9),
querying each address found in the local NIT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from functools import wraps
from typing import AsyncGenerator

from django.conf import settings
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
    StreamingHttpResponse,
)
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from ..ncp.client.tcp import NcpClient
from ..ncp.protocol.commands.request_snapshot import (
    RequestSnapshotRequest,
    RequestSnapshotResponse,
)
from ..ncp.protocol.frame import NcpCommandId
from .state import get_state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

_LOGIN_URL = "/login/"
_DASHBOARD_URL = "/dashboard/"


def _is_authenticated(request: HttpRequest) -> bool:
    return request.session.get("authenticated", False) is True


def login_required(view_fn):
    """Decorator: redirect to login if the session has no 'authenticated' flag."""

    @wraps(view_fn)
    async def wrapper(request: HttpRequest, *args, **kwargs):
        if not _is_authenticated(request):
            return HttpResponseRedirect(_LOGIN_URL)
        return await view_fn(request, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Node data collector
# ---------------------------------------------------------------------------

_SNAPSHOT_CACHE: dict[str, tuple[dict, float]] = {}  # address → (data, ts)
_CACHE_TTL = 8.0  # seconds before re-querying


async def _fetch_remote_snapshot(address: str, ncp_port: int) -> dict | None:
    """Fetch a snapshot from a remote node via NCP REQUEST_SNAPSHOT."""
    now = time.time()
    cached, ts = _SNAPSHOT_CACHE.get(address, ({}, 0.0))
    if cached and now - ts < _CACHE_TTL:
        return cached

    client = NcpClient(address=address, port=ncp_port, timeout=3.0)
    result = await client.send(
        NcpCommandId.REQUEST_SNAPSHOT,
        RequestSnapshotRequest().to_payload(),
    )
    if result.is_err():
        logger.debug("REQUEST_SNAPSHOT to %s failed: %s", address, result.unwrap_err())
        return None

    resp = RequestSnapshotResponse.from_payload(result.unwrap().payload)
    if resp.is_err():
        return None

    data = resp.unwrap().snapshot
    _SNAPSHOT_CACHE[address] = (data, now)
    return data


async def _collect_all_nodes() -> list[dict]:
    """Collect snapshots from the local node + all NIT peers."""
    state = get_state()

    # Local node (direct call — no network)
    local_snap = state.snapshot_fn()
    local_snap["is_local"] = True
    nodes = [local_snap]

    # Remote nodes listed in the NIT
    local_addr = local_snap.get("node", {}).get("address", "")
    remote_addrs = [
        entry.address
        for entry in state.nit._entries.values()  # pylint: disable=protected-access
        if entry.address != local_addr
    ]

    tasks = [_fetch_remote_snapshot(addr, state.ncp_port) for addr in remote_addrs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for addr, snap in zip(remote_addrs, results):
        if isinstance(snap, dict) and snap:
            snap["is_local"] = False
            nodes.append(snap)
        elif snap and not isinstance(snap, Exception):
            pass  # None — node unreachable

    return nodes


def _extract_promotions(nodes: list[dict]) -> list[dict]:
    """Aggregate and deduplicate quorum promotions from all node snapshots.

    Args:
        nodes: List of node snapshot dicts (each may contain ``quorum.promotions``).

    Returns:
        list[dict]: Deduplicated promotions sorted newest first.
    """
    seen: set[tuple] = set()
    all_promotions: list[dict] = []
    for snap in nodes:
        for promo in snap.get("quorum", {}).get("promotions", []):
            key = (promo.get("epoch"), promo.get("address"))
            if key not in seen:
                seen.add(key)
                all_promotions.append(promo)
    all_promotions.sort(key=lambda p: p.get("promoted_at", 0.0), reverse=True)
    return all_promotions


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def index(request: HttpRequest) -> HttpResponse:
    """Redirect / → dashboard (or login if not authenticated)."""
    if _is_authenticated(request):
        return HttpResponseRedirect(_DASHBOARD_URL)
    return HttpResponseRedirect(_LOGIN_URL)


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    """Login page — GET: show form, POST: validate credentials."""
    if _is_authenticated(request):
        return HttpResponseRedirect(_DASHBOARD_URL)

    error = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        if (
            username == settings.USMD_WEB_USERNAME
            and password == settings.USMD_WEB_PASSWORD
        ):
            request.session["authenticated"] = True
            request.session.set_expiry(0)  # expire on browser close
            return HttpResponseRedirect(_DASHBOARD_URL)
        error = "Identifiant ou mot de passe incorrect."

    return render(request, "login.html", {"error": error})


def logout_view(request: HttpRequest) -> HttpResponse:
    """Clear the session and redirect to login."""
    request.session.flush()
    return HttpResponseRedirect(_LOGIN_URL)


@login_required
async def dashboard(request: HttpRequest) -> HttpResponse:
    """Main dashboard — all nodes with resource bars."""
    nodes = await _collect_all_nodes()
    promotions = _extract_promotions(nodes)
    return render(
        request,
        "dashboard.html",
        {
            "nodes": nodes,
            "promotions": promotions,
            "now": time.time(),
        },
    )


@login_required
async def node_detail(request: HttpRequest, address: str) -> HttpResponse:
    """Detail page for a single node: NIT, NAL, NEL, resources."""
    state = get_state()
    local_addr = state.snapshot_fn().get("node", {}).get("address", "")
    if address in (local_addr, "local"):
        snap = state.snapshot_fn()
        snap["is_local"] = True
    else:
        snap = await _fetch_remote_snapshot(address, state.ncp_port)
        if not snap:
            return render(
                request,
                "node_detail.html",
                {
                    "error": f"Nœud {address} injoignable.",
                    "address": address,
                },
            )
        snap["is_local"] = False

    return render(request, "node_detail.html", {"node_data": snap, "address": address})


@login_required
async def api_nodes(_request: HttpRequest) -> JsonResponse:
    """JSON endpoint — list of all nodes with their latest snapshot."""
    nodes = await _collect_all_nodes()
    return JsonResponse(
        {
            "nodes": nodes,
            "promotions": _extract_promotions(nodes),
            "ts": time.time(),
        }
    )


@login_required
async def api_stream(_request: HttpRequest) -> StreamingHttpResponse:
    """Server-Sent Events endpoint — pushes node data every 5 seconds."""

    async def event_generator() -> AsyncGenerator[bytes, None]:
        while True:
            try:
                nodes = await _collect_all_nodes()
                payload = json.dumps(
                    {
                        "nodes": nodes,
                        "promotions": _extract_promotions(nodes),
                        "ts": time.time(),
                    }
                )
                yield f"data: {payload}\n\n".encode()
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("SSE generator error: %s", exc)
                yield f"data: {json.dumps({'error': str(exc)})}\n\n".encode()
            await asyncio.sleep(5)

    response = StreamingHttpResponse(
        event_generator(),
        content_type="text/event-stream",
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response
