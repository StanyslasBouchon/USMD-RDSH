"""Django views for the USMD-RDSH web dashboard.

Authentication uses simple username/password stored in Django settings
(sourced from NodeConfig.web_username / web_password).  No database is
required: session state is stored in a signed cookie.

Remote node data is fetched via the NCP REQUEST_SNAPSHOT command (ID 9),
querying each address found in the local NIT.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import time
from functools import wraps
from typing import AsyncGenerator, Iterable

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

# Human-readable French labels for each NodeState value
_STATE_REASONS: dict[str, str] = {
    "inactive":                                    "Inactif",
    "inactive_timeout":                            "Délai NCP dépassé",
    "inactive_nndp_no_here_i_am":                  "Aucun HIA reçu",
    "inactive_mutating":                           "En mutation",
    "inactive_emergency":                          "Urgence",
    "inactive_emergency_out_of_resources":         "Ressources insuffisantes",
    "inactive_emergency_dependency_inactive":      "Dépendance inactive",
    "inactive_emergency_health_check_failed":      "Vérification santé échouée",
    "inactive_emergency_update_failed":            "Mise à jour échouée",
    "excluded_invalid_nit":                        "NIT invalide (exclu)",
    "excluded_invalid_endorsement":                "Endorsement invalide (exclu)",
    "excluded_unverifiable_endorsement":           "Endorsement invérifiable (exclu)",
    "excluded_invalid_revocation":                 "Révocation invalide (exclu)",
    "excluded_invalid_endorsement_revocation":     "Révocation endorsement invalide (exclu)",
}


def _get_state_reason(state_value: str) -> str:
    """Return a human-readable French label for a NodeState value."""
    return _STATE_REASONS.get(state_value, "")


def _normalize_nrt_rows(snap: dict, usd_nodes: Iterable | None = None) -> None:
    """Ensure each NRT row exposes ``node_name`` for templates / JSON clients.

    - Rows are **shallow-copied** into a new list so we never mutate lists that
      may still be referenced from the snapshot cache.
    - If the key ``node_name`` is **absent** (vieux daemons), it is dérivée de
      l'USD du nœud qui héberge le dashboard (meilleur effort).
    - Si la clé est présente avec la valeur ``None`` (JSON ``null``), elle est
      **laissée telle quelle** : c'est la vérité du nœud source, à ne pas
      remplacer par l'USD local (sinon la colonne « référence » ment).
    """
    nrt = snap.get("nrt")
    if not nrt:
        return
    addr_to_name: dict[str, int] = {}
    if usd_nodes is not None:
        for n in usd_nodes:
            a = getattr(n, "address", None)
            if a and a not in addr_to_name:
                addr_to_name[a] = n.name
    out: list = []
    for row in nrt:
        if not isinstance(row, dict):
            out.append(row)
            continue
        r = dict(row)
        if "node_name" not in r:
            addr = r.get("address")
            r["node_name"] = addr_to_name.get(addr) if addr else None
        out.append(r)
    snap["nrt"] = out


def _invalidate_snapshot_cache(address: str) -> None:
    """Remove any cached snapshot for *address* (e.g. after a node goes inactive)."""
    _SNAPSHOT_CACHE.pop(address, None)


def _build_inactive_stub(address: str, usd_node) -> dict:
    """Build a minimal snapshot dict for a node known to be inactive.

    Avoids any NCP poll while still surfacing the node on the dashboard.
    """
    state_val = usd_node.state.value
    return {
        "is_local": False,
        "node": {
            "address": address,
            "name": usd_node.name,
            "state": state_val,
            "state_reason": _get_state_reason(state_val),
            "role": "unknown",
            "uptime_seconds": 0,
        },
        "resources": {
            "cpu_percent": 0.0,
            "ram_percent": 0.0,
            "disk_percent": 0.0,
            "network_percent": 0.0,
            "reference_load": 0.0,
        },
        "usd": {},
        "nit": [],
        "nal": [],
        "nel": [],
        "nrt": [],
        "nrl": [],
        "reference_nodes": [],
        "quorum": {"elected_roles": [], "promotions": []},
    }


async def _fetch_remote_snapshot(address: str, ncp_port: int) -> dict | None:
    """Fetch a snapshot from a remote node via NCP REQUEST_SNAPSHOT."""
    now = time.time()
    cached, ts = _SNAPSHOT_CACHE.get(address, ({}, 0.0))
    if cached and now - ts < _CACHE_TTL:
        # Copie profonde : les vues ne doivent jamais muter l'objet en cache
        # (sinon NRT / normalisation « collent » entre requêtes et TTL).
        return copy.deepcopy(cached)

    client = NcpClient(address=address, port=ncp_port, timeout=3.0)
    result = await client.send(
        NcpCommandId.REQUEST_SNAPSHOT,
        RequestSnapshotRequest().to_payload(),
    )
    if result.is_err():
        logger.debug("REQUEST_SNAPSHOT to %s failed: %s", address, result.unwrap_err())
        _invalidate_snapshot_cache(address)
        state = get_state()
        if state.on_ncp_failure:
            state.on_ncp_failure(address)
        return None

    resp = RequestSnapshotResponse.from_payload(result.unwrap().payload)
    if resp.is_err():
        return None

    data = resp.unwrap().snapshot
    _SNAPSHOT_CACHE[address] = (data, now)
    return copy.deepcopy(data)


async def _collect_all_nodes() -> list[dict]:
    """Collect snapshots from the local node + all peers.

    Inactive nodes (state != ACTIVE in the USD) are included as lightweight
    stub entries without any NCP poll.  Only nodes whose USD state is active
    (or whose state is unknown, e.g. not yet registered in the USD) are queried
    via NCP REQUEST_SNAPSHOT.
    """
    state = get_state()

    # Local node (direct call — no network)
    local_snap = state.snapshot_fn()
    local_snap["is_local"] = True
    nodes = [local_snap]

    local_addr = local_snap.get("node", {}).get("address", "")

    # Build address → USD node map (excluding self)
    addr_to_usd_node = {
        n.address: n
        for n in state.usd.nodes.values()
        if n.address != local_addr
    }

    # Union of NIT peers and USD-known peers so stale-but-known nodes stay visible
    nit_addrs = {
        entry.address
        for entry in state.nit.iter_all_entries()
        if entry.address != local_addr
    }
    all_remote_addrs = nit_addrs | set(addr_to_usd_node.keys())

    # Partition: inactive nodes get a stub, others are polled via NCP
    active_addrs: list[str] = []
    for addr in all_remote_addrs:
        usd_node = addr_to_usd_node.get(addr)
        if usd_node is not None and not usd_node.state.is_active():
            nodes.append(_build_inactive_stub(addr, usd_node))
        else:
            active_addrs.append(addr)

    tasks = [_fetch_remote_snapshot(addr, state.ncp_port) for addr in active_addrs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for addr, snap in zip(active_addrs, results):
        if isinstance(snap, dict) and snap:
            snap["is_local"] = False
            nodes.append(snap)

    usd_node_list = list(state.usd.nodes.values())
    # Enrich every snapshot with a human-readable state reason + NRT node_name
    for node_snap in nodes:
        node_info = node_snap.get("node")
        if isinstance(node_info, dict):
            node_info.setdefault(
                "state_reason", _get_state_reason(node_info.get("state", ""))
            )
        _normalize_nrt_rows(node_snap, usd_node_list)

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


async def _resolve_node_snapshot(address: str) -> tuple[dict | None, str | None]:
    """Load the status snapshot for *address* (local shortcut, stub, or NCP).

    Returns:
        ``(snapshot, None)`` on success, or ``(None, error_message)`` if the
        active remote peer is unreachable.
    """
    state = get_state()
    local_addr = state.snapshot_fn().get("node", {}).get("address", "")
    if address in (local_addr, "local"):
        snap = state.snapshot_fn()
        snap["is_local"] = True
    else:
        usd_node = next(
            (n for n in state.usd.nodes.values() if n.address == address),
            None,
        )
        if usd_node is not None and not usd_node.state.is_active():
            snap = _build_inactive_stub(address, usd_node)
        else:
            snap = await _fetch_remote_snapshot(address, state.ncp_port)
            if not snap:
                return None, f"Nœud {address} injoignable."
            snap["is_local"] = False
            node_info = snap.get("node")
            if isinstance(node_info, dict):
                node_info.setdefault(
                    "state_reason", _get_state_reason(node_info.get("state", ""))
                )

    _normalize_nrt_rows(snap, list(state.usd.nodes.values()))
    return snap, None


@login_required
async def node_detail(request: HttpRequest, address: str) -> HttpResponse:
    """Detail page for a single node: NIT, NAL, NEL, resources."""
    snap, err = await _resolve_node_snapshot(address)
    if err:
        return render(
            request,
            "node_detail.html",
            {"error": err, "address": address},
        )

    return render(
        request,
        "node_detail.html",
        {"node_data": snap, "address": address, "error": None},
    )


@login_required
async def api_node_snapshot(_request: HttpRequest, address: str) -> JsonResponse:
    """JSON snapshot for a single node — used by the fiche nœud (polling).

    Avoids ``/api/nodes/`` + ``find()`` : même adresse ou types JSON différents
    ne peuvent plus mélanger deux nœuds ni fausser la colonne « référence » NRT.
    """
    snap, err = await _resolve_node_snapshot(address)
    if err or snap is None:
        return JsonResponse({"error": err or "inconnu"}, status=503)
    return JsonResponse({"node": snap, "ts": time.time()})


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
            except Exception as exc:
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
