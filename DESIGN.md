---
name: Apex Agent Control Plane
description: A clear operations map for scoped AI systems.
colors:
  canvas: "#f7f8fc"
  surface: "#ffffff"
  ink: "#14213a"
  muted: "#60708b"
  rule: "#e0e6f0"
  primary: "#263ac2"
  active: "#e8ecff"
  coral: "#ef6548"
  green: "#4db399"
typography:
  display:
    fontFamily: "Manrope, Segoe UI, sans-serif"
    fontSize: "3.35rem"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "-0.04em"
  body:
    fontFamily: "Manrope, Segoe UI, sans-serif"
    fontSize: "0.92rem"
    fontWeight: 400
    lineHeight: 1.7
  label:
    fontFamily: "DM Mono, monospace"
    fontSize: "0.61rem"
    fontWeight: 400
rounded:
  control: "8px"
  panel: "14px"
spacing:
  compact: "0.55rem"
  control: "0.85rem"
  section: "2.5rem"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    padding: "0.85rem 1rem"
  panel-map:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
---

# Design System: Apex Agent Control Plane

## Overview

**Creative North Star: "The Operations Map"**

Apex is a light, focused systems board for operators who need to understand how an agent is connected before they investigate its records. The primary object is a real topology canvas, not a dashboard wall. Scope, durable flow, and evidence storage are all visible in the same reading direction.

**Key Characteristics:**

- A light workspace with a compact, utility-first sidebar.
- Cobalt routes signal safe movement through the system.
- Coral and green carry explicit state only; they never decorate idle content.
- A map is the visual center; attention appears as a tight queue alongside it.

## Colors

White surfaces and blue-gray rules make the topology legible during long operating sessions. Cobalt is the single active color. Coral marks priority; green marks configured state.

**The Map-Only Grid Rule.** Fine grid lines are permitted only inside an actual topology or measurement canvas.

## Typography

**Display Font:** Manrope (with Segoe UI fallback)
**Body Font:** Manrope (with Segoe UI fallback)
**Label/Mono Font:** DM Mono

Headings are compact, high-confidence situation labels. Body copy is quiet, plain language. Mono is reserved for times, scope, and environment state.

## Layout

Desktop uses a compact 238px sidebar and a wide working field. The map and attention queue form the primary two-column operation. Tablet collapses the sidebar to icons; mobile moves essential navigation to the bottom and reshapes the map nodes into a vertical flow.

## Elevation & Depth

Panels use borders and tonal fields, not shadows. Map nodes are simple white objects over the map canvas. Motion is limited to the topology nodes appearing in causal order; reduced-motion users see the finished state immediately.

## Shapes

Controls use an 8px radius; large map and note panels use a 14px radius. State dots stay circular. Wide pills and repeated equal-size cards are excluded.

## Components

### Buttons

- **Primary:** cobalt, white text, concise action verb, 8px radius.
- **Secondary:** white with a cool-gray border; used for filters and utilities.
- **Focus:** visible high-contrast outline; never color alone.

### Navigation

- White utility sidebar with cobalt active state.
- Icons are consistent line icons, accompanied by labels on desktop.
- Mobile exposes only the most important destinations.

### Map

- A topology canvas is the first-class operational object.
- Node labels name the system component and its known state.
- Dashed lines communicate illustrative or pending routing; live state must be server-derived.

## Do's and Don'ts

### Do:

- **Do** make an agent's scope, event path, and evidence destination readable together.
- **Do** distinguish sample, empty, loading, denied, and live data in copy and state.
- **Do** use the map grid only to aid spatial reading of the topology.

### Don't:

- **Don't** lead with metric cards, decorative gradients, or an arbitrary dark dashboard shell.
- **Don't** imply security posture or connectivity from sample data.
- **Don't** render agent-provided values as HTML or make browser state authoritative.
