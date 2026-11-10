import { defineConfig } from "@playwright/test";

// End-to-end against the real API: FastAPI serves the built UI, the dev OIDC issuer and the
// controller WebSocket on one port, backed by a throwaway SQLite database.
export default defineConfig({
  testDir: "tests",
  workers: 1,
  use: { baseURL: "http://localhost:8000", trace: "retain-on-failure" },
  webServer: {
    command: "npm run build && cd .. && rm -f e2e.db && DATABASE_URL=sqlite:///./e2e.db TAILGATE_MODEL=stub "
      + "${PYTHON:-python3} -m uvicorn app.main:app --port 8000",
    url: "http://localhost:8000/healthz",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
