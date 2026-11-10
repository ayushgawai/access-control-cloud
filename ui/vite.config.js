import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the API so the UI and the dev issuer share one origin, like production
// (where FastAPI serves ui/dist itself).
const api = "http://localhost:8000";
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": api, "/oidc": api, "/ws": { target: api, ws: true } } },
});
