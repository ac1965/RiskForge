import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// ADR 0013: proxy /api to `riskforge serve` in dev so internal/api never
// needs CORS handling. Override the target with RISKFORGE_API_URL if
// `riskforge serve` isn't on its default address.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: process.env.RISKFORGE_API_URL ?? "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
});
