import { StrictMode, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

// --- OIDC authorization code + PKCE against the API's issuer ------------------------------------
const CLIENT_ID = "admin-ui";
const REDIRECT_URI = `${location.origin}/callback`;
const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));

async function login() {
  const verifier = random(32);
  const state = random(16);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  sessionStorage.setItem("pkce", JSON.stringify({ verifier, state }));
  location.assign(`/oidc/authorize?${new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: "openid profile email",
    code_challenge: b64url(new Uint8Array(digest)), code_challenge_method: "S256", state,
  })}`);
}

async function finishLogin() {
  const params = new URLSearchParams(location.search);
  const { verifier, state } = JSON.parse(sessionStorage.getItem("pkce") || "{}");
  sessionStorage.removeItem("pkce");
  history.replaceState(null, "", "/");
  if (!params.get("code") || params.get("state") !== state) throw new Error("login state mismatch");
  const res = await fetch("/oidc/token", {
    method: "POST",
    body: new URLSearchParams({ grant_type: "authorization_code", code: params.get("code"), redirect_uri: REDIRECT_URI,
                                client_id: CLIENT_ID, code_verifier: verifier }),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  sessionStorage.setItem("token", (await res.json()).access_token);
}

// Module level so StrictMode's double-run effects can't redeem the one-time code twice.
const boot = location.pathname === "/callback" ? finishLogin() : Promise.resolve();

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${sessionStorage.getItem("token")}`, "Content-Type": "application/json" },
  });
  if (res.status === 401) { sessionStorage.removeItem("token"); location.reload(); }
  if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText);
  return res.status === 204 ? null : res.json();
}

const RANK = { viewer: 1, operator: 2, admin: 3 };

// --- views -------------------------------------------------------------------------------------
function Doors({ me, notify }) {
  const [doors, setDoors] = useState([]);
  const load = useCallback(() => api("/doors").then(setDoors).catch(notify), [notify]);
  useEffect(() => { load(); }, [load]);
  const operator = RANK[me.role] >= RANK.operator;

  const toggle = (d) => api(`/doors/${d.id}`, { method: "PATCH", body: JSON.stringify({ mode: d.mode === "lockdown" ? "normal" : "lockdown" }) })
    .then(load).catch(notify);
  const requestUnlock = (d) => {
    const reason = prompt(`Why unlock ${d.name}?`);
    if (reason) api(`/doors/${d.id}/unlock-requests`, { method: "POST", body: JSON.stringify({ reason }) })
      .then(() => notify(`Unlock for ${d.name} requested; waiting for an admin to approve.`)).catch(notify);
  };
  return (
    <table>
      <thead><tr><th>Door</th><th>Camera</th><th>Mode</th><th>Controller</th>{operator && <th />}</tr></thead>
      <tbody>{doors.map((d) => (
        <tr key={d.id} data-testid={`door-${d.id}`}>
          <td>{d.name}</td><td><code>{d.camera_id}</code></td>
          <td className={d.mode === "lockdown" ? "bad" : ""}>{d.mode}</td>
          <td className={d.online ? "ok" : ""}>{d.online ? "online" : "offline"}</td>
          {operator && <td>
            <button onClick={() => toggle(d)}>{d.mode === "lockdown" ? "End lockdown" : "Lock down"}</button>{" "}
            <button onClick={() => requestUnlock(d)}>Request unlock</button>
          </td>}
        </tr>))}
      </tbody>
    </table>
  );
}

function Events({ notify }) {
  const [events, setEvents] = useState([]);
  const [tailgateOnly, setTailgateOnly] = useState(false);
  const [clip, setClip] = useState(null);
  useEffect(() => {
    const load = () => api(`/events?limit=100${tailgateOnly ? "&tailgate=true" : ""}`).then(setEvents).catch(notify);
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [tailgateOnly, notify]);
  return (
    <>
      <div className="bar">
        <button aria-pressed={tailgateOnly} onClick={() => setTailgateOnly(!tailgateOnly)}>Tailgates only</button>
        <span className="warn">{events.filter((e) => e.tailgate).length} tailgate(s) in view</span>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Door</th><th>Badge</th><th>Decision</th><th>Reason</th><th>People</th><th>Clip</th></tr></thead>
        <tbody>{events.map((e) => (
          <tr key={e.id} data-testid="event-row">
            <td>{new Date(e.ts).toLocaleString()}</td><td>{e.door_id}</td><td><code>{e.badge}</code></td>
            <td><span className={`tag ${e.granted ? "ok" : "bad"}`}>{e.granted ? "granted" : "denied"}</span>
              {e.tailgate && <> <span className="tag warn">tailgate</span></>}</td>
            <td>{e.reason}</td><td>{e.people_count}</td>
            <td>{e.clip_id && <button onClick={() => api(`/clips/${e.clip_id}`).then(setClip).catch(notify)}>View</button>}</td>
          </tr>))}
        </tbody>
      </table>
      {clip && (
        <div className="panel" data-testid="clip">
          <strong>{clip.clip_id}</strong> <code>{clip.url}</code>
          <p>{clip.start} → {clip.end} · detector: {clip.detector} · max people: {clip.people_count}
            {clip.tailgate && <span className="tag warn"> tailgate</span>}</p>
          <button onClick={() => setClip(null)}>Close</button>
        </div>
      )}
    </>
  );
}

function Approvals({ me, notify }) {
  const [requests, setRequests] = useState([]);
  const load = useCallback(() => api("/unlock-requests?status=pending").then(setRequests).catch(notify), [notify]);
  useEffect(() => { load(); }, [load]);
  const decide = (r, action) => api(`/unlock-requests/${r.id}/${action}`, { method: "POST" })
    .then((res) => { notify(`Request ${r.id} ${res.status}${res.delivered ? " and sent to the door" : ""}.`); load(); })
    .catch(notify);
  if (!requests.length) return <p>No pending unlock requests.</p>;
  return (
    <table>
      <thead><tr><th>#</th><th>Door</th><th>Reason</th><th>Requested by</th><th>When</th>{me.role === "admin" && <th />}</tr></thead>
      <tbody>{requests.map((r) => (
        <tr key={r.id} data-testid="unlock-request">
          <td>{r.id}</td><td>{r.door_id}</td><td>{r.reason}</td><td><code>{r.requested_by}</code></td>
          <td>{new Date(r.created_at).toLocaleString()}</td>
          {me.role === "admin" && <td>
            <button className="primary" onClick={() => decide(r, "approve")}>Approve</button>{" "}
            <button onClick={() => decide(r, "deny")}>Deny</button>
          </td>}
        </tr>))}
      </tbody>
    </table>
  );
}

function App() {
  const [me, setMe] = useState(null);
  const [tab, setTab] = useState("doors");
  const [notice, setNotice] = useState("");
  const [ready, setReady] = useState(false);
  const notify = useCallback((e) => setNotice(String(e?.message ?? e)), []);

  useEffect(() => {
    boot
      .then(() => sessionStorage.getItem("token") && api("/me").then(setMe))
      .catch(notify)
      .finally(() => setReady(true));
  }, [notify]);

  if (!ready) return null;
  if (!me) return (
    <div className="center"><div>
      <h1>Access Control Admin</h1>
      <p>Sign in through the organization's OIDC provider.</p>
      <button className="primary" onClick={login}>Sign in</button>
      {notice && <p className="bad">{notice}</p>}
    </div></div>
  );
  const tabs = { doors: "Doors", events: "Access events", approvals: "Unlock approvals" };
  return (
    <>
      <header>
        <h1>Access Control Admin</h1>
        <span data-testid="whoami"><code>{me.sub}</code> · org {me.org_id} · {me.role}</span>
        <button onClick={() => { sessionStorage.removeItem("token"); setMe(null); }}>Sign out</button>
      </header>
      <nav>{Object.entries(tabs).map(([k, label]) => (
        <button key={k} aria-pressed={tab === k} onClick={() => { setTab(k); setNotice(""); }}>{label}</button>))}
      </nav>
      <main>
        {notice && <p role="status">{notice}</p>}
        {tab === "doors" && <Doors me={me} notify={notify} />}
        {tab === "events" && <Events notify={notify} />}
        {tab === "approvals" && <Approvals me={me} notify={notify} />}
      </main>
    </>
  );
}

createRoot(document.getElementById("root")).render(<StrictMode><App /></StrictMode>);
