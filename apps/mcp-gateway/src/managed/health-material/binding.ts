import { RuntimeConfigurationSchema, RuntimeLaunchContextSchema, encodeJson,
  type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import { GatewayError } from "../../contracts.js";
import { parseRuntimeConfiguration } from "../runtime-config.js";
import { parseRuntimeLaunchContext } from "../launch-context.js";
import { assertDataTree, assertMessage, freezeTree, requireValue } from "../runtime-config/boundary.js";
import type { ReadinessBinding } from "../readiness/types.js";

/** Same generated/passive boundary as the accepted bound codec; no report
 * validator, authority brand, or expected metadata derived from staged files. */
export function copyBinding(input: ReadinessBinding): ReadinessBinding {
  assertDataTree(input, true);
  requireValue(input && Object.keys(input).length === 2 && Object.keys(input).every(k => k === "config" || k === "launch"));
  assertMessage(RuntimeConfigurationSchema, input.config);
  assertMessage(RuntimeLaunchContextSchema, input.launch);
  const config = parseRuntimeConfiguration(encodeJson(RuntimeConfigurationSchema, input.config as RuntimeConfiguration));
  const launch = parseRuntimeLaunchContext(encodeJson(RuntimeLaunchContextSchema, input.launch as RuntimeLaunchContext), config);
  return freezeTree({ config, launch });
}

/** Fixed canonical43 ASCII -> exact32 bytes, identical to the 6G token format.
 * Decode directly from mutable bytes without creating an immutable secret string.
 * Canonical unpadded base64url requires the final two padding bits to be zero. */
export function decodeToken(bytes: Buffer): Buffer {
  if (bytes.length !== 43) throw rejected();
  const token = Buffer.alloc(32);
  try {
    let pending = 0, bits = 0, output = 0;
    for (const byte of bytes) {
      const value = byte >= 65 && byte <= 90 ? byte - 65 : byte >= 97 && byte <= 122 ? byte - 71 :
        byte >= 48 && byte <= 57 ? byte + 4 : byte === 45 ? 62 : byte === 95 ? 63 : -1;
      if (value < 0) throw rejected();
      pending = (pending << 6) | value; bits += 6;
      if (bits >= 8) { bits -= 8; token[output++] = pending >> bits; pending &= (1 << bits) - 1; }
    }
    if (output !== 32 || bits !== 2 || pending !== 0) throw rejected();
    return token;
  } catch { token.fill(0); throw rejected(); }
}
export function rejected(): GatewayError { return new GatewayError("INVALID_INPUT", "health material rejected safely"); }
