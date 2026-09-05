import type { Plugin, ProxyOptions } from "vite";

export function browserEdgeProxyLogging(): Plugin {
  return {
    name: "apex-browser-edge-proxy-logging",
    apply: "serve",
    configResolved({ logger }) {
      const error = logger.error.bind(logger);
      // Vite installs its HTTP error listener AFTER ProxyOptions.configure.
      // Sanitize at its logger sink; keep the listener's response handling and
      // the original forwarded URL intact. Never pass raw Error/options along.
      logger.error = (message, options) => {
        if (/^(?:\u001b\[[0-9;]*m)*http proxy error:/.test(message)) {
          error("Browser edge proxy request failed.", { timestamp: true });
        } else {
          error(message, options);
        }
      };
    },
  };
}

export function browserEdgeProxy(target: string | undefined): Record<string, ProxyOptions> | undefined {
  if (target === undefined) return undefined;
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(target);
  if (!match || match[0] !== target || Number(match[1]) > 65535) {
    throw new Error("APEX_UI_BROWSER_EDGE must be an explicit http://127.0.0.1:port origin");
  }
  // Only a local development hop. Do not rewrite Origin, redirects or cookies
  // to evade the Rust edge's HTTPS-origin/session/CSRF requirements.
  return { "^/(api|auth)(/|$)": { target, changeOrigin: false, followRedirects: false,
    ws: false, timeout: 65000, proxyTimeout: 65000 } };
}
