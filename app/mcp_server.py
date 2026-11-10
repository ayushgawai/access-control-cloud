"""MCP server so an AI assistant can investigate access incidents.

It is a thin client of the REST API and authenticates with an org-scoped API token, so the
assistant can never see more than that token's org and role allow. Use an *operator* token:
it can file unlock requests but cannot approve them; only a different human admin can.

  ACC_API_URL=http://localhost:8000 ACC_API_TOKEN=acc_dev_mcp python -m app.mcp_server
"""
from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("access-control")
client = httpx.Client(base_url=os.getenv("ACC_API_URL", "http://localhost:8000"),
                      headers={"Authorization": f"Bearer {os.getenv('ACC_API_TOKEN', 'acc_dev_mcp')}"}, timeout=10)


def _call(method: str, path: str, **kw):
    r = client.request(method, path, **kw)
    if r.is_error:
        raise ValueError(f"API {r.status_code}: {r.text}")
    return r.json()


def _params(**kw) -> dict:
    return {k: v for k, v in kw.items() if v is not None}


@mcp.tool()
def list_doors(site_id: int | None = None) -> list[dict]:
    """List doors with their site, camera, mode (normal or lockdown) and whether the controller is online."""
    return _call("GET", "/api/doors", params=_params(site_id=site_id))


@mcp.tool()
def search_access_events(door_id: int | None = None, badge: str | None = None, granted: bool | None = None,
                         tailgate: bool | None = None, since: str | None = None, until: str | None = None,
                         limit: int = 50) -> list[dict]:
    """Search badge decisions, newest first. `since`/`until` are ISO-8601 timestamps.
    Each event has granted/reason, the rule that matched, a clip_id and a tailgate flag."""
    return _call("GET", "/api/events", params=_params(door_id=door_id, badge=badge, granted=granted,
                                                      tailgate=tailgate, since=since, until=until, limit=limit))


@mcp.tool()
def get_clip(clip_id: str) -> dict:
    """Fetch the video clip linked to an access event: time range, URL, per-frame person counts
    and the tailgating verdict."""
    return _call("GET", f"/api/clips/{clip_id}")


@mcp.tool()
def unlock_door_with_approval(door_id: int, reason: str) -> dict:
    """Ask for a remote door unlock. This NEVER unlocks directly: it files a pending request that a
    human admin must approve in the admin UI. Report the request id to the user and poll
    get_unlock_request; do not claim the door is open until status is 'approved'."""
    return _call("POST", f"/api/doors/{door_id}/unlock-requests", json={"reason": reason})


@mcp.tool()
def get_unlock_request(request_id: int) -> dict:
    """Check whether an unlock request is pending, approved or denied, and by whom."""
    return _call("GET", f"/api/unlock-requests/{request_id}")


if __name__ == "__main__":
    mcp.run(transport=os.getenv("MCP_TRANSPORT", "stdio"))
