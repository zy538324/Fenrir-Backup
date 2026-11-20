import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API to a local fenrir-server.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 800 },
  server: {
    proxy: {
      "/api": { target: "https://localhost:8443", secure: false },
      "/install": { target: "https://localhost:8443", secure: false },
      "/uninstall": { target: "https://localhost:8443", secure: false },
      "/agent": { target: "https://localhost:8443", secure: false },
    },
  },
});
