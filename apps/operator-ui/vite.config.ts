import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { browserEdgeProxy, browserEdgeProxyLogging } from "./dev-proxy";

export default defineConfig(({ command }) => {
  const proxy = command === "serve" ? browserEdgeProxy(process.env.APEX_UI_BROWSER_EDGE) : undefined;
  return {
    plugins: [react(), ...(proxy ? [browserEdgeProxyLogging()] : [])],
    server: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
    preview: { host: "127.0.0.1", port: 4173 },
  };
});
