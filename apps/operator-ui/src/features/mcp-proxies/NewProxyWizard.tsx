import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Check, CircleAlert, LockKeyhole, Save, ShieldCheck, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { previewProxyApi, requestId } from "./api";
import { emptyWizardDraft, type ProxyDraft, type ProxyWizardDraft } from "./types";

const steps = ["Identity", "Ingress", "Upstream", "Tools", "CLI", "Governance", "Review"] as const;
const scope = { workspaceId: "northstar-research", namespaceId: "research" } as const;

export function NewProxyWizard() {
  const navigate = useNavigate();
  const created = useRef(false);
  const [draftInfo, setDraftInfo] = useState<ProxyDraft>();
  const [form, setForm] = useState<ProxyWizardDraft>(emptyWizardDraft());
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState("Creating a server-side draft…");
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    if (created.current) return;
    created.current = true;
    void previewProxyApi.create({ displayName: "New governed proxy", slug: `managed-proxy-${Date.now()}`, ...scope, requestId: requestId() }).then((draft) => {
      setDraftInfo(draft);
      setForm(emptyWizardDraft("New governed proxy", `managed-proxy-${draft.proxyId.slice(0, 8)}`));
      setBusy(false);
      setMessage("Draft created. Nothing is deployed until you review and confirm.");
    }).catch(() => { setBusy(false); setMessage("The control plane could not create a safe draft."); setErrors(["Draft creation failed. Retry from the proxy inventory."]); });
  }, []);

  const update = <K extends keyof ProxyWizardDraft>(field: K, value: ProxyWizardDraft[K]) => setForm((current) => ({ ...current, [field]: value }));

  async function save(): Promise<boolean> {
    if (!draftInfo) return false;
    setBusy(true);
    try {
      await previewProxyApi.updateDraft({ proxyId: draftInfo.proxyId, expectedRevisionId: draftInfo.revisionId, patch: form, requestId: requestId() });
      setBusy(false);
      setMessage("Draft saved to the control plane.");
      return true;
    } catch {
      setBusy(false);
      setMessage("The draft changed or could not be saved safely.");
      return false;
    }
  }

  function next() {
    const stepErrors = validateStep(step, form);
    setErrors(stepErrors);
    if (stepErrors.length === 0) { void save().then((saved) => { if (saved) setStep((current) => Math.min(steps.length - 1, current + 1)); }); }
  }

  async function deploy() {
    if (!draftInfo) return;
    const saved = await save();
    if (!saved) return;
    setBusy(true);
    const report = await previewProxyApi.validate({ proxyId: draftInfo.proxyId, revisionId: draftInfo.revisionId });
    if (!report.valid) { setErrors([...report.errors]); setBusy(false); setMessage("Validation found issues. Review the highlighted configuration."); return; }
    try {
      await previewProxyApi.publish({ proxyId: draftInfo.proxyId, expectedRevisionId: draftInfo.revisionId, requestId: requestId() });
      await previewProxyApi.deploy({ proxyId: draftInfo.proxyId, revisionId: draftInfo.revisionId, requestId: requestId() });
      await navigate({ to: "/mcp-proxies/$proxyId", params: { proxyId: draftInfo.proxyId } });
    } catch { setBusy(false); setMessage("Deployment failed safely. The draft remains available for correction."); }
  }

  return <main id="main-content" className="proxy-page wizard-page"><header className="app-header"><div className="crumb"><Link to="/mcp-proxies">MCP proxies</Link><span>/</span><strong>New proxy</strong></div><Link className="wizard-cancel" to="/mcp-proxies"><X size={16} /> Cancel</Link></header>
    <div className="wizard-heading"><div><p className="eyebrow">Create a governed boundary</p><h1>New MCP proxy</h1><p>Configure one isolated proxy. Server validation, policy, and deployment authority remain in Apex.</p></div><div className="draft-badge"><span className="draft-dot" />{draftInfo ? `Draft ${draftInfo.revisionId.slice(0, 8)}…` : "Preparing draft"}</div></div>
    <ol className="wizard-steps" aria-label="Proxy creation steps">{steps.map((label, index) => <li key={label} className={index === step ? "active" : index < step ? "complete" : ""}><button type="button" onClick={() => index < step && setStep(index)} aria-current={index === step ? "step" : undefined} disabled={index > step}>{index < step ? <Check size={14} /> : <span>{index + 1}</span>}{label}</button></li>)}</ol>
    <section className="wizard-card"><div className="wizard-card-head"><div><span className="step-kicker">Step {step + 1} of {steps.length}</span><h2>{steps[step]}</h2></div><span className="server-note"><ShieldCheck size={15} /> server-authoritative</span></div>{busy && <div className="wizard-status" role="status">{message}</div>}{!busy && message && <div className="wizard-status" role="status">{message}</div>}{errors.length > 0 && <div className="wizard-errors" role="alert"><CircleAlert size={17} /><div><strong>Review before continuing</strong>{errors.map((error) => <span key={error}>{error}</span>)}</div></div>}
      <WizardFields step={step} form={form} update={update} />
      <div className="wizard-safety"><LockKeyhole size={17} /><span>Secrets never enter this browser flow. Use a named <code>secret://</code> reference; the runtime resolves it only inside the managed boundary.</span></div>
      <div className="wizard-actions"><button className="secondary-button" type="button" onClick={() => void save()} disabled={busy || !draftInfo}><Save size={15} /> Save draft</button><div><button className="secondary-button" type="button" onClick={() => setStep((current) => Math.max(0, current - 1))} disabled={step === 0 || busy}><ArrowLeft size={15} /> Back</button>{step < steps.length - 1 ? <button className="primary-button" type="button" onClick={next} disabled={busy || !draftInfo}>Continue <ArrowRight size={15} /></button> : <button className="primary-button" type="button" onClick={() => void deploy()} disabled={busy || !draftInfo}><ShieldCheck size={15} /> Validate & deploy</button>}</div></div>
    </section>
  </main>;
}

function WizardFields({ step, form, update }: { step: number; form: ProxyWizardDraft; update: <K extends keyof ProxyWizardDraft>(field: K, value: ProxyWizardDraft[K]) => void }) {
  if (step === 0) return <div className="form-grid"><Field label="Display name" value={form.displayName} onChange={(value) => update("displayName", value)} placeholder="Research portfolio tools" /><Field label="Stable slug" value={form.slug} onChange={(value) => update("slug", value)} placeholder="research-portfolio-tools" /><Select label="Environment" value={form.environment} onChange={(value) => update("environment", value as ProxyWizardDraft["environment"])} options={["local", "staging", "production"]} /><div className="field-help">Identity is scoped to <strong>Northstar research / research</strong>. It cannot be changed by the browser after creation.</div></div>;
  if (step === 1) return <div className="form-grid"><Select label="Inbound transport" value={form.ingress} onChange={(value) => update("ingress", value as ProxyWizardDraft["ingress"])} options={["streamable-http", "stdio"]} /><Field label="Published endpoint" value={form.endpoint} onChange={(value) => update("endpoint", value)} placeholder="https://proxy.example.test/mcp" /><div className="field-help">HTTP endpoints must be HTTPS, declared, and revalidated on every redirect and DNS answer.</div></div>;
  if (step === 2) return <div className="form-grid"><Field label="Upstream name" value={form.upstreamName} onChange={(value) => update("upstreamName", value)} placeholder="Portfolio service" /><Field label="Upstream endpoint" value={form.endpoint} onChange={(value) => update("endpoint", value)} placeholder="https://portfolio.example.test/mcp" /><Field label="Credential reference" value={form.upstreamCredentialRef} onChange={(value) => update("upstreamCredentialRef", value)} placeholder="secret://portfolio/read" /><div className="field-help">Discovery is quarantined. Only explicitly selected tools can be exposed, even when upstream discovery returns more.</div></div>;
  if (step === 3) return <div className="form-grid"><Field label="Exposed tool alias" value={form.exposedTool} onChange={(value) => update("exposedTool", value)} placeholder="portfolio.read" /><div className="tool-selection"><span className="tool-quarantine">QUARANTINED DISCOVERY</span><strong>portfolio.read</strong><small>Read-only · selected exposure</small><button type="button" onClick={() => update("exposedTool", "portfolio.read")}>Select this tool</button></div><div className="field-help">Tool aliases are an explicit allowlist. Discovery metadata is untrusted input until selected and validated by the server.</div></div>;
  if (step === 4) return <div className="form-grid"><Field label="Fixed CLI profile" value={form.cliProfile} onChange={(value) => update("cliProfile", value)} placeholder="portfolio.inspect" /><div className="cli-preview"><strong>Safe runner posture</strong><span>Fixed executable · shell disabled · bounded argv · sanitized environment · output capped</span></div><div className="field-help">CLI profiles reference an approved server-side executable and digest. Arbitrary commands cannot be entered here.</div></div>;
  if (step === 5) return <div className="form-grid"><Field label="Inbound issuer" value={form.authIssuer} onChange={(value) => update("authIssuer", value)} placeholder="https://issuer.example.test" /><Field label="Audience" value={form.authAudience} onChange={(value) => update("authAudience", value)} placeholder="apex-mcp-proxy" /><Field label="Apex policy ID" value={form.policyId} onChange={(value) => update("policyId", value)} placeholder="research-read-only" /><Select label="Classification" value={form.classification} onChange={(value) => update("classification", value as ProxyWizardDraft["classification"])} options={["public", "internal", "confidential", "restricted"]} /><Select label="Approval mode" value={form.approvalMode} onChange={(value) => update("approvalMode", value as ProxyWizardDraft["approvalMode"])} options={["none", "on-demand", "always"]} /><Field label="Budget / minute" value={form.budgetPerMinute} onChange={(value) => update("budgetPerMinute", value)} placeholder="60" /></div>;
  return <Review form={form} />;
}

function Review({ form }: { form: ProxyWizardDraft }) {
  return <div className="review-grid"><div className="review-panel"><span>IDENTITY</span><strong>{form.displayName || "Unnamed proxy"}</strong><small>{form.slug || "No slug"} · {form.environment}</small></div><div className="review-panel"><span>INGRESS / UPSTREAM</span><strong>{form.ingress}</strong><small>{form.endpoint || "No endpoint"} · {form.upstreamName || "No upstream"}</small></div><div className="review-panel"><span>EXPOSURE</span><strong>{form.exposedTool || "No tool selected"}</strong><small>CLI: {form.cliProfile || "No profile"}</small></div><div className="review-panel"><span>GOVERNANCE</span><strong>{form.policyId || "No policy"}</strong><small>{form.classification} · approval {form.approvalMode}</small></div><div className="redacted-diff"><ShieldCheck size={18} /><div><strong>Redacted review</strong><p>Credential values, tokens, and runtime internals are intentionally omitted. Only the reference name <code>{form.upstreamCredentialRef || "secret://"}</code> will be sent to the control plane.</p></div></div></div>;
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder: string }) {
  return <label className="form-field"><span>{label}</span><input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /></label>;
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: readonly string[] }) {
  return <label className="form-field"><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}>{options.map((option) => <option key={option}>{option}</option>)}</select></label>;
}

function validateStep(step: number, form: ProxyWizardDraft): string[] {
  if (step === 0) return [!form.displayName && "Display name is required", !form.slug && "Stable slug is required"].filter(Boolean) as string[];
  if (step === 1) return [!form.endpoint.startsWith("https://") && "Published endpoint must use HTTPS"].filter(Boolean) as string[];
  if (step === 2) return [!form.upstreamName && "Upstream name is required", !form.endpoint.startsWith("https://") && "Upstream endpoint must use HTTPS", !form.upstreamCredentialRef.startsWith("secret://") && "Use a secret:// credential reference"].filter(Boolean) as string[];
  if (step === 3) return [!form.exposedTool && "Select one explicitly exposed tool"].filter(Boolean) as string[];
  if (step === 5) return [!form.policyId && "Apex policy ID is required", !form.authIssuer.startsWith("https://") && "Inbound issuer must use HTTPS"].filter(Boolean) as string[];
  return [];
}
