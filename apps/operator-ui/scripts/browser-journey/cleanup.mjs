// One owner for frontend/browser shutdown, including cancellation during launch.
export function createCleanup({ getLaunching, closeFrontend, notifyBrowser, emergencyExit,
  intervalMs = 250, timeoutMs = 4_000 }) {
  let cleaning;
  return () => {
    if (cleaning) return cleaning;
    cleaning = (async () => {
      const emergency = setTimeout(() => { clearInterval(nudge); emergencyExit(); }, timeoutMs);
      const nudge = setInterval(notifyBrowser, intervalMs);
      try {
        const launching = getLaunching();
        // A rejected launch has no Browser to close; the caller still reports
        // its original failure. Do NOT catch rejection of a launched close.
        const closedBrowser = launching ? launching.then(owned => owned.close(), () => {}) : Promise.resolve();
        await Promise.all([closeFrontend(), closedBrowser]);
      } catch {
        // No PASS and no raw dependency error. Keep the exact-owned-tree
        // notifications and emergency exit alive when graceful close fails.
        throw new Error('cleanup');
      }
      clearInterval(nudge); clearTimeout(emergency);
    })();
    return cleaning;
  };
}
