import base64
import hashlib
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.websockets import WebSocketDisconnect

from app import main

WED_10AM_LA = datetime(2026, 11, 11, 18, 0, tzinfo=timezone.utc)
SAT_10AM_LA = datetime(2026, 11, 14, 18, 0, tzinfo=timezone.utc)
CONTROLLER = "acc_dev_controller"


def badge(client, door_id: int, badge_id: str, people: int = 1) -> dict:
    with client.websocket_connect(f"/ws/controllers/{door_id}?token={CONTROLLER}") as ws:
        ws.send_json({"type": "badge", "badge": badge_id, "req_id": 7, "sim_people": people})
        reply = ws.receive_json()
    assert reply["type"] == "decision" and reply["req_id"] == 7
    return reply


@pytest.fixture
def at(monkeypatch):
    def pin(when):
        monkeypatch.setattr(main, "now", lambda: when)

    pin(WED_10AM_LA)
    return pin


# --- OIDC -------------------------------------------------------------------------------------

def pkce():
    verifier = "v" * 50
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def test_oidc_authorization_code_with_pkce(client):
    disco = client.get("/oidc/.well-known/openid-configuration").json()
    assert disco["code_challenge_methods_supported"] == ["S256"]
    assert client.get("/oidc/jwks").json()["keys"][0]["alg"] == "RS256"

    verifier, challenge = pkce()
    redirect = "http://localhost:5173/callback"
    form = client.get("/oidc/authorize", params={"client_id": "admin-ui", "redirect_uri": redirect,
                                                 "code_challenge": challenge, "state": "xyz"})
    assert form.status_code == 200 and "alice@example.test" in form.text
    r = client.post("/oidc/authorize", data={"client_id": "admin-ui", "redirect_uri": redirect,
                                             "code_challenge": challenge, "state": "xyz", "membership": "2:1"},
                    follow_redirects=False)
    assert r.status_code == 302
    qs = parse_qs(urlparse(r.headers["location"]).query)
    assert qs["state"] == ["xyz"]
    code = qs["code"][0]

    bad = client.post("/oidc/token", data={"grant_type": "authorization_code", "code": code, "client_id": "admin-ui",
                                           "redirect_uri": redirect, "code_verifier": "wrong" * 10})
    assert bad.status_code == 400  # wrong verifier also burns the code
    r = client.post("/oidc/authorize", data={"client_id": "admin-ui", "redirect_uri": redirect,
                                             "code_challenge": challenge, "membership": "2:1"},
                    follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    tok = client.post("/oidc/token", data={"grant_type": "authorization_code", "code": code, "client_id": "admin-ui",
                                           "redirect_uri": redirect, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    headers = {"Authorization": f"Bearer {tok.json()['access_token']}"}
    assert client.get("/api/me", headers=headers).json() == {"sub": "user:2", "org_id": 1, "role": "operator",
                                                             "kind": "user"}
    replay = client.post("/oidc/token", data={"grant_type": "authorization_code", "code": code,
                                              "client_id": "admin-ui", "redirect_uri": redirect,
                                              "code_verifier": verifier})
    assert replay.status_code == 400


def test_oidc_rejects_unregistered_redirect(client):
    _, challenge = pkce()
    r = client.get("/oidc/authorize", params={"client_id": "admin-ui", "redirect_uri": "https://evil.test/cb",
                                              "code_challenge": challenge})
    assert r.status_code == 400


# --- authz ------------------------------------------------------------------------------------

def test_roles_and_missing_tokens(client, carol, bob):
    assert client.get("/api/doors").status_code == 401
    assert client.get("/api/doors", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert len(client.get("/api/doors", headers=carol).json()) == 4
    assert client.post("/api/sites", headers=carol, json={"name": "X"}).status_code == 403
    assert client.post("/api/sites", headers=bob, json={"name": "X"}).status_code == 403
    assert client.get("/api/doors", headers={"Authorization": f"Bearer {CONTROLLER}"}).status_code == 403


def test_org_isolation(client, dave):
    assert client.get("/api/doors", headers=dave).json() == []
    assert client.patch("/api/doors/1", headers=dave, json={"mode": "lockdown"}).status_code == 404
    site = client.post("/api/sites", headers=dave, json={"name": "Annex", "timezone": "Europe/Berlin"}).json()
    # Cannot point a rule in org 2 at org 1's credential.
    r = client.post("/api/rules", headers=dave, json={"effect": "allow", "site_id": site["id"], "credential_id": 1})
    assert r.status_code == 404


def test_validation(client, alice):
    assert client.post("/api/sites", headers=alice, json={"name": "A", "timezone": "Mars/Base"}).status_code == 422
    r = client.post("/api/rules", headers=alice, json={"effect": "allow", "door_id": 1, "site_id": 1, "group": "x"})
    assert r.status_code == 422
    r = client.post("/api/credentials", headers=alice, json={"holder": "Dup", "badge": "1001"})
    assert r.status_code == 409


def test_api_tokens(client, alice):
    t = client.post("/api/tokens", headers=alice, json={"name": "reporting", "role": "viewer"}).json()
    h = {"Authorization": f"Bearer {t['token']}"}
    assert client.get("/api/doors", headers=h).status_code == 200
    assert client.post("/api/sites", headers=h, json={"name": "X"}).status_code == 403
    assert all("token_hash" not in x for x in client.get("/api/tokens", headers=alice).json())
    assert client.delete(f"/api/tokens/{t['id']}", headers=alice).status_code == 204
    assert client.get("/api/doors", headers=h).status_code == 401


# --- decisions over the controller socket -----------------------------------------------------

def test_controller_socket_rejects_bad_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/controllers/1?token=acc_nope") as ws:
            ws.receive_json()


def test_decisions_follow_schedules_and_rules(client, at):
    assert badge(client, 3, "1002")["reason"] == "rule_allow"  # staff, business hours
    assert badge(client, 4, "1002")["reason"] == "rule_deny"  # roof hatch denies staff
    assert badge(client, 1, "1003")["reason"] == "credential_expired"
    assert badge(client, 1, "1004")["reason"] == "credential_suspended"
    assert badge(client, 1, "9999")["reason"] == "unknown_credential"
    at(SAT_10AM_LA)
    assert badge(client, 3, "1002")["reason"] == "outside_schedule"
    assert badge(client, 2, "1001")["granted"]  # IT group: server room always


def test_admin_changes_apply_immediately(client, at, bob):
    assert badge(client, 3, "1002")["granted"]
    assert client.patch("/api/credentials/2", headers=bob, json={"status": "lost"}).status_code == 200
    assert badge(client, 3, "1002")["reason"] == "credential_lost"
    client.patch("/api/credentials/2", headers=bob, json={"status": "active"})
    client.patch("/api/doors/3", headers=bob, json={"mode": "lockdown"})
    assert badge(client, 3, "1002")["reason"] == "door_lockdown"
    client.patch("/api/doors/3", headers=bob, json={"mode": "normal"})
    assert badge(client, 3, "1002")["granted"]


def test_events_are_logged_with_clip_and_tailgate(client, at, carol, alice):
    reply = badge(client, 1, "1001", people=2)
    assert reply["granted"]
    ev = client.get(f"/api/events/{reply['event_id']}", headers=carol).json()
    assert ev["tailgate"] and ev["people_count"] == 2 and ev["clip_id"].startswith("clip_cam-1_")
    clip = client.get(f"/api/clips/{ev['clip_id']}", headers=carol).json()
    assert clip["tailgate"] and max(f["people"] for f in clip["frames"]) == 2 and clip["detector"] == "stub"
    hits = client.get("/api/events", headers=carol, params={"tailgate": True, "door_id": 1}).json()
    assert reply["event_id"] in {e["id"] for e in hits}
    audit = client.get("/api/audit", headers=alice).json()
    assert any(a["action"] == "tailgate:detected" and a["detail"]["event_id"] == reply["event_id"] for a in audit)

    calm = badge(client, 1, "1001", people=1)
    assert not client.get(f"/api/events/{calm['event_id']}", headers=carol).json()["tailgate"]


# --- remote unlock approval gate --------------------------------------------------------------

def test_unlock_requires_a_second_admin(client, alice, bob):
    req = client.post("/api/doors/1/unlock-requests", headers=bob, json={"reason": "visitor at lobby"}).json()
    assert req["status"] == "pending"
    assert client.post(f"/api/unlock-requests/{req['id']}/approve", headers=bob).status_code == 403  # operator

    with client.websocket_connect(f"/ws/controllers/1?token={CONTROLLER}") as ws:
        r = client.post(f"/api/unlock-requests/{req['id']}/approve", headers=alice)
        assert r.status_code == 200 and r.json()["delivered"]
        assert ws.receive_json() == {"type": "unlock", "request_id": req["id"], "duration_s": 5}
    assert client.post(f"/api/unlock-requests/{req['id']}/approve", headers=alice).status_code == 409

    own = client.post("/api/doors/1/unlock-requests", headers=alice, json={"reason": "my own"}).json()
    assert client.post(f"/api/unlock-requests/{own['id']}/approve", headers=alice).status_code == 403
    actions = [a["action"] for a in client.get("/api/audit", headers=alice).json()]
    assert "unlock:requested" in actions and "unlock:approved" in actions
