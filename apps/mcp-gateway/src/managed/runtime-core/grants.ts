import { DeploymentGrantOwner } from "../authority/grant-owner.js";
import type { GrantOwnerOptions, GrantSnapshot } from "../authority/types.js";

/** Every renewal path, including the exposed owner, revokes this generation on
 * refusal. Replacement continuity is checked by the owner before overwriting. */
export class RuntimeGrants extends DeploymentGrantOwner {
  private samplingReadiness = false;
  constructor(options: GrantOwnerOptions, private readonly revoke: () => void,
    private readonly ready: () => boolean = () => false) { super(options); }
  /** Authority continuity is independent of readiness; avoids snapshot recursion
   * through the monitor's ADMISSION owner and complete-binding currentness gate. */
  authoritySnapshot(): GrantSnapshot { return super.snapshot(); }
  override snapshot(): GrantSnapshot {
    const before = super.snapshot();
    let ready = false;
    if (before.admitting && !this.samplingReadiness) {
      this.samplingReadiness = true;
      try { ready = this.ready() === true; } catch { /* Readiness fails closed. */ }
      finally { this.samplingReadiness = false; }
    }
    const after = super.snapshot();
    return Object.freeze({ ...after, admitting: ready && after.admitting && before.epoch === after.epoch &&
      before.decisionId === after.decisionId });
  }
  override async renew(): Promise<boolean> {
    const accepted = await super.renew();
    if (!accepted || this.authoritySnapshot().mode === "closed") { this.revoke(); return false; }
    return true;
  }
}
