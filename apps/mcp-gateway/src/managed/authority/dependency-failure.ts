// Internal provenance only. No public error fields, remote text, status coercion,
// or caller-supplied properties can turn an unknown refusal into a retry signal.
const unavailable = new WeakSet<Error>();

export function dependencyUnavailable(message: string): Error {
  const error = new Error(message); unavailable.add(error); return error;
}
export function isDependencyUnavailable(error: unknown): boolean {
  return typeof error === "object" && error !== null && unavailable.has(error as Error);
}
export function redactDependencyFailure(error: unknown, message: string): Error {
  return isDependencyUnavailable(error) ? dependencyUnavailable(message) : new Error(message);
}
export function ordinaryGrpcStatus(status: unknown): boolean {
  return status === "8" || status === "14";
}
