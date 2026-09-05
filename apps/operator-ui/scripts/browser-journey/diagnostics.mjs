import { responseCategories } from './response.mjs';

const categories = new Set(['configuration', 'protocol', 'transport', 'browser', 'traffic', 'login', 'scope',
  'cookie', 'cookie_lifetime', 'privacy', 'artifact', 'identity', 'inventory', 'offline', 'logout', 'response', 'assertion',
  'cancelled', 'deadline', 'internal', 'cleanup', 'journey', ...responseCategories]);

// Failure-only diagnostics. Never serialize an exception or browser data.
export function createDiagnostics() {
  let phase = 'configuration';
  return {
    phase(value) { phase = categories.has(value) ? value : 'internal'; },
    category(error) {
      return error instanceof Error && categories.has(error.message) ? error.message : phase;
    },
  };
}
