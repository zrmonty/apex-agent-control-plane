import { requireValue } from './policy.mjs';

const operations = new Set(['initial_inventory', 'create', 'detail_reload', 'inventory_reload', 'restored_inventory']);
const stages = ['wait', 'status', 'cache', 'body', 'size', 'utf8', 'json'];
export const responseCategories = Object.freeze([...operations].flatMap(operation =>
  stages.map(stage => `response_${operation}_${stage}`)));

// Test-runner diagnostics only. The deferred source retains the journey's
// action-before-body ordering; "wait" includes that action and response wait.
// No request matching, retries, deadlines or acceptance rules change here.
export async function jsonResponse(operation, obtainResponse, onPhase) {
  requireValue(operations.has(operation), 'internal');
  let category = 'internal';
  const phase = stage => { category = `response_${operation}_${stage}`; onPhase(category); };
  try {
    phase('wait');
    const response = await obtainResponse();
    phase('status');
    requireValue(response.status() === 200, category);
    phase('cache');
    requireValue(response.headers()['cache-control'] === 'no-store', category);
    phase('body');
    const bytes = await response.body();
    phase('size');
    requireValue(bytes.length <= 1024 * 1024, category);
    phase('utf8');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    category = 'privacy';
    requireValue(!/(?:access_token|refresh_token|id_token|accessToken|refreshToken|idToken)/.test(text), category);
    phase('json');
    return { response, value: JSON.parse(text) };
  } catch {
    // Discard the original exception, including its message, stack and cause.
    throw new Error(category);
  }
}
