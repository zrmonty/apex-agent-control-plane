import type { Writable } from "node:stream";

/** Process-lifetime ownership: write callbacks precede Writable error events.
 * Do not remove these listeners when a callback settles or retry a failed stream. */
export function ownHealthOutput(stdout: Writable, stderr: Writable) {
  type Channel = "stdout" | "stderr";
  let listener: ((channel: Channel) => void) | undefined;
  const failures = new Set<Channel>();
  function own(stream: Writable, channel: Channel) {
    let pending: ((error: Error) => void) | undefined;
    stream.on("error", () => {
      failures.add(channel); pending?.(Error()); listener?.(channel);
    });
    return (line: string) => new Promise<void>((resolve, reject) => {
      if (failures.has(channel)) { reject(Error()); return; }
      pending = reject;
      try {
        stream.write(line, error => {
          // Drain callback-following error events before reporting a successful flush.
          setImmediate(() => {
            pending = undefined;
            if (error || failures.has(channel)) reject(Error()); else resolve();
          });
        });
      } catch { pending = undefined; reject(Error()); }
    });
  }
  const write = own(stdout, "stdout"), error = own(stderr, "stderr");
  return { write, error, onError(callback: (channel: Channel) => void) {
    listener = callback; for (const channel of failures) callback(channel);
  } };
}
