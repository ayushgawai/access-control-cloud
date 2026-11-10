# access-control-cloud

A cloud physical-security platform: sites, doors, credentials, schedules and access rules; simulated
door controllers that badge in over WebSockets; every decision paired with a camera clip and checked
for tailgating; an MCP server so an AI assistant can investigate incidents, with a human approval gate
on remote unlocks.

```
 simulated door controllers        React admin UI                  AI assistant
 (app/loadtest.py, compose)        OIDC code + PKCE                     │ MCP (stdio)
          │ WebSocket                     │ REST                        ▼
          ▼                               ▼                     app/mcp_server.py
 ┌──────────────────────────── FastAPI  app/main.py ──────── REST + API token ┐
 │  /ws/controllers/{door}        /api/*            /oidc/*  (local dev issuer) │
 │         │                         │  admin writes ─┐                        │
 │         ▼                         │                ▼                        │
 │  PolicyCache.get(org) ──▶ engine.decide()   invalidate(org)                 │
 │         │                 (pure stdlib)                                     │
 │         ├──▶ decision back to controller  (latency measured here)           │
 │         ▼                                                                   │
 │  video.clip_for(camera, ts) ──▶ PersonCounter: YOLO (ultralytics) | stub    │
 │         │                         └── granted && people ≥ 2 → tailgate     │
 │         ▼                                                                   │
 │  EventWriter: bulk insert every 50 ms; reads flush first                    │
 └─────────┬───────────────────────────────────────────────────────────────────┘
           ▼
   PostgreSQL (Docker Compose)  ·  SQLite (tests, quick local runs)
   access_events · audit_log · unlock_requests · rules · schedules · ...
```

## Design

| Concern | Choice | Why | Known ceiling |
|---|---|---|---|
| Decision path | `app/engine.py`, pure functions over a compiled per-org `Policy`; no DB on the hot path | p99 stays sub-millisecond in-process; the engine tests run without the web stack | One process holds every org's policy in memory |
| Rule semantics | Default deny; deny beats allow; schedules gate both; door- and site-level rules; target a credential or a group | Matches how badge systems are usually reasoned about; reasons are explicit (`outside_schedule`, `credential_lost`, ...) | No anti-passback, no occupancy limits |
| Cache coherence | Every admin write calls `invalidate(org)`; a version check stops a slow load from caching stale rules | A lost or suspended badge must stop working immediately (tested) | Per process; several replicas would need Postgres `LISTEN/NOTIFY` |
| Persistence | SQLAlchemy 2; PostgreSQL in Compose, SQLite in tests; `create_all`, no migrations | One code path for both | Add Alembic before schema changes |
| Event writes | Batched bulk insert every 50 ms in a writer thread; failed batches are re-queued | Keeps DB latency out of the decision | A crash can lose up to one unflushed batch; controllers don't replay yet |
| Audit | `access_events` is the decision trail (reason, rule, latency, clip, people, tailgate); `audit_log` records every admin action, unlock request/decision and tailgate | Investigations need both | Not tamper-evident (no hash chain) |
| AuthN | Local OIDC issuer: discovery, JWKS, authorization code + PKCE (S256), RS256 tokens; exact-match redirect URIs; single-use 60 s codes | Real OAuth 2.0/OIDC flow, swappable for a hosted IdP later | Dev issuer: pick-an-identity login, no passwords; key is per process unless `OIDC_PRIVATE_KEY_PEM` is set |
| AuthZ | Org-scoped roles `viewer < operator < admin`, plus `controller` for doors; every query filtered by the caller's org; cross-org references in bodies return 404 | Tenancy is enforced in one helper (`owned`) | No per-site scoping inside an org |
| API tokens | `acc_...`, SHA-256 hashed, org + role scoped, shown once, revocable; cannot mint above your own role | For controllers, the MCP server and scripts | No expiry |
| Remote unlock | Operator files a request; a *different* admin approves; the command goes to the live controller socket | AI assistants and people both go through the same gate | Requests don't expire |
| Camera linkage | Clip id = camera + timestamp; simulated NVR rebuilds metadata and frames deterministically | Every event links to a clip; tests are deterministic | Clips are synthetic |
| Tailgating | Max person count across the clip after one granted read; ≥ 2 → flagged and audited. YOLO through ultralytics when installed and the frame has an image, stub counter otherwise | Deterministic in tests, real model available | No tracking: two people badging one after another inside the clip window would be flagged |
| MCP | Official Python SDK (`FastMCP`), thin client of the REST API using an operator API token | The assistant sees only what its token allows and cannot approve unlocks | stdio transport by default |

## Run

Docker Compose (PostgreSQL, API with the built UI, four simulated controllers):

```bash
docker compose up --build
open http://localhost:8000          # Sign in -> pick alice (admin), bob (operator) or carol (viewer)
```

Without Docker (SQLite):

```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
(cd ui && npm ci && npm run build)  # optional: FastAPI serves ui/dist at /
uvicorn app.main:app --reload       # seeds a demo org on first start (SEED_DEMO=0 to skip)
python -m app.loadtest ws --doors 4 --events 1000 --interval 2   # simulated controllers
# UI dev server with hot reload instead of the build: (cd ui && npm run dev) -> http://localhost:5173
```

MCP server, for an MCP client such as Claude Desktop or Claude Code:

```json
{ "mcpServers": { "access-control": {
    "command": "python", "args": ["-m", "app.mcp_server"], "cwd": "/path/to/access-control-cloud",
    "env": { "ACC_API_URL": "http://localhost:8000", "ACC_API_TOKEN": "acc_dev_mcp" } } } }
```

Tools: `list_doors`, `search_access_events`, `get_clip`, `unlock_door_with_approval`, `get_unlock_request`.
`unlock_door_with_approval` only files a pending request; an admin approves it under **Unlock approvals** in the UI.

Seeded dev credentials (local only): users `alice` / `bob` / `carol` `@example.test` in Demo Org, `dave` in
Second Org; API tokens `acc_dev_controller` (controller) and `acc_dev_mcp` (operator); badges `1001` (staff+it),
`1002` (staff), `1003` (expired), `1004` (suspended).

Optional real person counting: `pip install ultralytics`, then `python -m app.video photo.jpg`.

## Test

```bash
pytest -q                                      # engine, OIDC/PKCE, RBAC, org isolation, WebSocket decisions,
                                               # clip + tailgate, unlock approval gate, MCP tools over the protocol
cd ui && npx playwright install chromium && npx playwright test
                                               # builds the UI, starts the real API on :8000 with a fresh SQLite DB,
                                               # signs in through the dev issuer and drives lockdown, unlock
                                               # approval and tailgate review end to end
cd infra/terraform && terraform init -backend=false && terraform validate   # never applied
```

CI (`.github/workflows/ci.yml`) runs all of the above plus the 5,000-door load test over WebSockets
against the Compose stack on PostgreSQL.

## Bench

```bash
python -m app.loadtest inproc --doors 5000 --events 5   # engine + clip + detector + batched SQLite writes, no network
SEED_DOORS=5000 docker compose up -d --build --wait db api
python -m app.loadtest ws --doors 5000 --events 5       # 5,000 controller WebSockets against the API on PostgreSQL
```

Each door badges with exponential gaps (mean 1 s), so 5,000 doors offer roughly 5,000 reads/s at peak.
About 3% of reads carry two people (tailgates). Latency is request → decision round trip as the
controller sees it.

Laptop sanity run (Apple Silicon Mac, Python 3.15, in-process mode, full 5,000 doors):

```
inproc doors=5000: 25000 decisions in 20.3s (1,233/s)  p50=0.04ms p95=0.10ms p99=0.17ms max=2.06ms  rows_written=25000 tailgates_flagged=301
```

Throughput here is bounded by the offered load (5 reads per door spread over ~20 s), not by the engine.
This number excludes the network, JSON over WebSockets and PostgreSQL: it shows the decision path
itself is not the bottleneck. The over-the-wire run is in CI; see below.

## Limitations

- **Verification scope.** Verified locally (2026-11-10): `pytest -q` — 21 passed; Playwright — 4 passed;
  UI production build succeeds; the in-process 5,000-door bench above. The Compose/PostgreSQL
  WebSocket load test and `terraform validate` are wired in CI (`.github/workflows/ci.yml`) and were
  not run locally in this environment; Terraform is never applied.
- The OIDC issuer is a development stand-in (no passwords, in-memory auth codes, one signing key per
  process). Production would point at a hosted IdP and map its claims to org roles; that mapping is not built.
- Single replica only: the policy cache, auth codes and the controller socket registry are in process.
- Event persistence is batched; a crash can drop up to one 50 ms batch, and controllers do not buffer or replay.
- No schema migrations, unlock-request expiry, token expiry, per-site roles, anti-passback or occupancy rules.
- Video is simulated. YOLO is wired in but only runs on real image frames (`python -m app.video`); the
  simulated clips always use the stub counter, and the YOLO path is not exercised in CI.
- The tailgate heuristic counts people, it does not track them, so two separately badged people inside
  one clip window would be a false positive.
- Controller tokens may be sent in the WebSocket query string (header also accepted); query strings can end up in proxy logs.
- Terraform is a skeleton: default VPC, HTTP-only ALB, public task IPs, `DATABASE_URL` wiring from the
  RDS secret left as a comment. It has only been validated, never applied.

## License

MIT, see [LICENSE](LICENSE).
