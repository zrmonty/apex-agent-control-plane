/** Fixed production ceilings. Only the private component boundary can reduce them. */
export const productionLimits = Object.freeze({ sockets: 128, requests: 120, controlRequests: 8, sessions: 64,
  sessionRequests: 8, sessionControlRequests: 1, executions: 128, sessionMs: 300000, requestMs: 120000,
  bodyMs: 5000, cleanupMs: 5000, startupMs: 5000 });
export type IngressLimits = { [K in keyof typeof productionLimits]: number };
export function ingressLimits(input: Partial<IngressLimits> = {}): IngressLimits {
  const result = { ...productionLimits, ...input };
  for (const key of Object.keys(result) as (keyof IngressLimits)[]) {
    if (!Object.hasOwn(productionLimits, key) || !Number.isSafeInteger(result[key]) || result[key] < 1 ||
      result[key] > productionLimits[key]) throw new Error("managed ingress limits refused safely");
  }
  return Object.freeze(result);
}
