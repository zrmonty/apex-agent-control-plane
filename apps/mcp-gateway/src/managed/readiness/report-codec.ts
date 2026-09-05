import { GatewayError } from "../../contracts.js";
import { ReadinessReportSchema, RuntimeConfigurationSchema, RuntimeLaunchContextSchema,
  decodeStrict, encodeJson, type ReadinessReport, type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import { assertDataTree, assertMessage, freezeTree, requireValue } from "../runtime-config/boundary.js";
import { parseRuntimeConfiguration } from "../runtime-config.js";
import { parseRuntimeLaunchContext, type ReadonlyRuntimeLaunchContext } from "../launch-context.js";
import { validateReport } from "./report-codec/semantics.js";
import type { ReadinessBinding, ReadonlyReadinessReport } from "./types.js";

/** Once-bound, independently copied config/launch metadata. The caller must own
 * authenticated provenance and a current lease; neither generated/frozen types
 * nor self-consistent hashes prove those. No I/O, wall-age or admission decisions. */
export class ReadinessReportCodec {
  readonly #launch: ReadonlyRuntimeLaunchContext;
  constructor(binding: ReadinessBinding) {
    try {
      assertDataTree(binding, true);
      requireValue(binding && Object.keys(binding).length === 2 && Object.keys(binding).every(key => key === "config" || key === "launch"));
      assertMessage(RuntimeConfigurationSchema, binding.config);
      assertMessage(RuntimeLaunchContextSchema, binding.launch);
      const config = parseRuntimeConfiguration(encodeJson(RuntimeConfigurationSchema, binding.config as RuntimeConfiguration));
      this.#launch = parseRuntimeLaunchContext(encodeJson(RuntimeLaunchContextSchema, binding.launch as RuntimeLaunchContext), config);
    } catch { throw rejected(); }
  }
  encode(report: ReadonlyReadinessReport): string {
    try { return this.checkedText(report); }
    catch { throw rejected(); }
  }
  decode(originalText: string): ReadonlyReadinessReport {
    try {
      // Preserve original duplicate/alias information; reject objects without
      // coercion, and bound UTF-8 before any strict-parser allocation.
      requireValue(typeof originalText === "string" && originalText.length <= 8192 && Buffer.byteLength(originalText, "utf8") <= 8192);
      assertDataTree(originalText, false);
      const report = decodeStrict(ReadinessReportSchema, originalText);
      this.checkedText(report);
      return freezeTree(report);
    }
    catch { throw rejected(); }
  }
  private checkedText(report: ReadonlyReadinessReport): string {
    assertDataTree(report, true);
    assertMessage(ReadinessReportSchema, report);
    validateReport(report, this.#launch);
    const text = JSON.stringify(encodeJson(ReadinessReportSchema, report as ReadinessReport));
    requireValue(Buffer.byteLength(text, "utf8") <= 8192);
    return text;
  }
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "readiness report rejected safely");
}
