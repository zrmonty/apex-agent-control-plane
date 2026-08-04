# Single-Agent Runtime View

**Status:** Accepted — core Operator UI surface  
**Mode:** Operate  
**Delivery:** Phase 1 operator UI

## Purpose

When an operator selects an agent in Fleet Canvas, Apex always opens a human-scale **Agent Story**. The view shows what one agent is, what it may do, and what it did in a specific run. The visual clarity matches a small reference agent. The operator stays inside Apex security, scope, and fleet context.

This is a core product promise. Apex must make a complex fleet intelligible one agent and one run at a time.

## What the operator sees

```text
Fleet Canvas → Agent → Agent Story → Select run → Runtime playback
```

The default view is a compact, generated runtime map:

```text
Trigger → policy/admission → model → decision → tool(s) → observation → completion
                        ↘ memory read/write (when observed)
                        ↘ child agent (when observed)
```

The map is generated from the agent's declared `WorkflowDescriptor`, execution profile, and actual scoped events. It is never a hand-authored decorative diagram:

- observed steps are solid and selectable;
- declared-but-not-observed capabilities are visibly inactive;
- unavailable data is labeled unavailable, never inferred;
- retries, fallbacks, tool calls, memory activity, child agents, denials, errors, and terminal outcomes appear in run order;
- the selected run is visually distinct from fleet aggregates.

The small reference agent therefore reads as a simple reason → act → observe loop. A complex multi-agent workflow expands progressively. The operator does not start with a fleet-scale graph.

## Required panels

| Panel | Operator question answered |
|---|---|
| Agent identity and scope | What is this agent, where is it allowed to operate, which revision and execution profile is active? |
| Runtime map | What are its actual loop, tools, decisions, memory actions, and child-agent relationships? |
| Run playback | What happened in this run, in what order, and where did time/cost/failure occur? |
| Model and Cost strip | Which requested/effective model and effort ran, did fallback occur, what did it cost, and how confident is the attribution? |
| Security and policy strip | Which policy was applied; was untrusted input, a tool call, egress, or a finding blocked/contained? |
| Health and diagnostics | Is it connected, degraded, blocked, failing, or behind on telemetry/control? What safe remediation exists? |

## Interaction model

1. **Overview first:** Show current health, latest run outcome, cost, policy posture, and one readable runtime map.
2. **Click a node or timeline event:** Reveal the redacted trace detail, decision reason, model attribution, tool policy, cost, error report, or related security finding.
3. **Playback:** Step through a run in timestamp and source-sequence order. Display late and duplicate events honestly. Do not rearrange history silently.
4. **Progressive disclosure:** An operator can expand a child agent, tool attempt, retry, or memory operation in place. Heavy trace tables remain available. They are never the starting experience.
5. **Safe action:** Permitted actions such as pause, drain, quarantine, or open a diagnostic bundle show their scope, policy effect, and required approval before execution.

## Security and truthfulness rules

- All data is authorized and redacted server-side before it reaches the view.
- Prompt, completion, tool-output, memory, and diagnostic content is untrusted data. Render it as inert text only when capture policy and viewer permission allow it.
- Content classified as untrusted is visibly marked. It can never become a clickable instruction, action label, authorization cue, or model or system prompt.
- Model, reasoning-effort, token, and cost values show requested, effective, and evidence confidence. Do not present estimates as actuals.
- Runtime topology is versioned and event-derived. Apex does not show an invented memory, tool, policy, or success step merely because a template expects one.
- A viewer can see only scope-allowed actions and trace fields. The UI never relies on hiding a control for enforcement.

## Reference-agent acceptance test

The Phase 1 reference-agent demo is complete only when an operator can click a single agent and, in one view, see:

1. its scope, workload identity state, prompt/code/model revision, and active policy profile;
2. a live or recorded reason → model → tool → observation → completion loop;
3. the model's requested/effective model and reasoning effort, usage, cost, retry/fallback state, and evidence confidence;
4. any child-agent branch and its return path;
5. a blocked untrusted control or tool event rendered as a redacted Security Center finding; and
6. a safe, authorized action or diagnostic deep link when the run is degraded or failed.

The view must remain legible at a laptop-sized viewport. It must be keyboard-operable. It must be available in high-contrast mode. It must be usable without reading raw JSON.

## Relationship to Waku-style reference agents

Apex preserves the valuable reference-agent experience: the operator sees the loop and the pillars behind a run. Apex renders that view from auditable, scoped runtime evidence. It extends the view with policy, identity, cost, security, diagnostics, and multi-agent relationships when they exist.

The reference agent remains deliberately small. It is the visual and integration baseline. Apex must not require a customer to adopt a Waku-like memory system, gateway, or tool set to receive this view.


---

Writing style: [ASD-STE100 Simplified Technical English](../writing-style-ste100.md).
