import asyncio

import pytest

from app import mcp_server

MCP_TOKEN = {"Authorization": "Bearer acc_dev_mcp"}  # seeded operator token


class Authed:
    """Routes the MCP server's HTTP calls into the in-process app with its API token."""

    def __init__(self, client):
        self.client = client

    def request(self, method, path, **kw):
        return self.client.request(method, path, headers=MCP_TOKEN, **kw)


@pytest.fixture
def tools(client, monkeypatch):
    monkeypatch.setattr(mcp_server, "client", Authed(client))
    return mcp_server


def test_protocol_exposes_tools():
    from mcp.shared.memory import create_connected_server_and_client_session

    async def names():
        async with create_connected_server_and_client_session(mcp_server.mcp._mcp_server) as session:
            return {t.name for t in (await session.list_tools()).tools}

    assert asyncio.run(names()) == {"list_doors", "search_access_events", "get_clip", "unlock_door_with_approval",
                                    "get_unlock_request"}


def test_incident_investigation(tools, client):
    doors = tools.list_doors()
    assert {d["name"] for d in doors} == {"Lobby", "Server Room", "Loading Dock", "Roof Hatch"}

    with client.websocket_connect("/ws/controllers/2?token=acc_dev_controller") as ws:
        ws.send_json({"type": "badge", "badge": "1001", "req_id": 1, "sim_people": 3})
        event_id = ws.receive_json()["event_id"]
    hits = tools.search_access_events(door_id=2, tailgate=True)
    assert event_id in {e["id"] for e in hits}
    clip = tools.get_clip(next(e["clip_id"] for e in hits if e["id"] == event_id))
    assert clip["tailgate"] and clip["people_count"] == 3
    with pytest.raises(ValueError, match="404"):
        tools.get_clip("clip_nope_1")


def test_unlock_goes_through_human_approval(tools, client, alice):
    req = tools.unlock_door_with_approval(door_id=2, reason="tech locked out during incident")
    assert req["status"] == "pending"
    # The assistant's operator token cannot approve its own request.
    assert client.post(f"/api/unlock-requests/{req['id']}/approve", headers=MCP_TOKEN).status_code == 403
    assert tools.get_unlock_request(req["id"])["status"] == "pending"
    client.post(f"/api/unlock-requests/{req['id']}/approve", headers=alice)
    assert tools.get_unlock_request(req["id"])["status"] == "approved"
