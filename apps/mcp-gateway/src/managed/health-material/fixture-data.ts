import { artifactText } from "../runtime-config/test-support.js";
import { source } from "../launch-context/test-support.js";
import { parseRuntimeConfiguration } from "../runtime-config.js";
import { parseRuntimeLaunchContext } from "../launch-context.js";

/** TEST ONLY: real Rust-exported config plus independent synthetic launch/owner.
 * Never derives expected metadata from the staged slots being checked. */
export function fixtureData() {
  const config = parseRuntimeConfiguration(artifactText);
  const launchText = JSON.stringify(source());
  const launch = parseRuntimeLaunchContext(launchText, config);
  // Deterministic public test material, NOT credential issuance/staging policy.
  const token = Buffer.alloc(32, 0xa5);
  return { expected: Object.freeze({ config, launch }), configText: artifactText, launchText, token,
    files: [Buffer.from(artifactText), Buffer.from(launchText), Buffer.from(token.toString("base64url"), "ascii")] };
}
