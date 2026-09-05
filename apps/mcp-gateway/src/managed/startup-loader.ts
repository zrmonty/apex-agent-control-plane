import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { GatewayError } from "../contracts.js";
import { parseRuntimeConfiguration, type ReadonlyRuntimeConfiguration } from "./runtime-config.js";

const MAX_CONFIG_BYTES = 262144;

/** Absence means no configuration, not permission to serve standalone. Process
 * selection is validated separately before loading. Inline legacy configuration is no longer a
 * supported startup source, including empty inline values or two supplied vars.
 * Publication/catalog provenance remains a trusted provisioning precondition. */
export async function loadRuntimeConfiguration(env: NodeJS.ProcessEnv): Promise<ReadonlyRuntimeConfiguration | undefined> {
  const file = env.APEX_MCP_PROXY_REVISION_CONFIG_FILE;
  if (env.APEX_MCP_PROXY_REVISION_CONFIG !== undefined) throw rejected();
  if (file === undefined) return undefined;
  if (!file.length || file.trim() !== file || file.length > 4096 || file.includes("\0")) throw rejected();
  try {
    const before = await lstat(file);
    if (!before.isFile() || before.size < 1 || before.size > MAX_CONFIG_BYTES) throw rejected();
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino ||
        opened.size < 1 || opened.size > MAX_CONFIG_BYTES) throw rejected();
      // A growing file cannot cause an unbounded allocation/read or be silently
      // truncated into a valid prefix: read one byte beyond the accepted bound.
      const bytes = Buffer.alloc(MAX_CONFIG_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const read = await handle.read(bytes, length, bytes.length - length, null);
        if (read.bytesRead === 0) break;
        length += read.bytesRead;
      }
      if (length === 0 || length > MAX_CONFIG_BYTES) throw rejected();
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
      return parseRuntimeConfiguration(text); // Original text, including duplicate keys.
    } finally { await handle.close(); }
  } catch { throw rejected(); }
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "managed runtime configuration rejected safely");
}
