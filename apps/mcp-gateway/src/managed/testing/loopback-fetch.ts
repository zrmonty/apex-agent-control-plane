import { request } from "node:http";
import { Readable } from "node:stream";

/** Component-only HTTPS termination simulation: send to a local listener while
 * preserving the configured resource Host. Native fetch ignores custom Host on
 * this Node build. This helper does not alter production TLS/Origin policy. */
export function loopbackFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: init.method, headers: Object.fromEntries(new Headers(init.headers)),
      signal: init.signal ?? undefined, agent: false }, res => {
      const headers = new Headers();
      for (const [name, value] of Object.entries(res.headers)) {
        for (const entry of Array.isArray(value) ? value : value === undefined ? [] : [value]) headers.append(name, entry);
      }
      resolve(new Response([204, 304].includes(res.statusCode!) ? null
        : Readable.toWeb(res) as ReadableStream<Uint8Array>, { status: res.statusCode, headers }));
    });
    req.on("error", reject);
    req.end(typeof init.body === "string" ? init.body : undefined);
  });
}
