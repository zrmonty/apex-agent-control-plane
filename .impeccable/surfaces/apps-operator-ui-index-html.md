---
version: 1
slug: "apps-operator-ui-index-html"
primary_target: "apps/operator-ui/index.html"
related_targets: ["apps/operator-ui/src/main.tsx"]
---

# Phase 1 operator UI

Mode: Operate.

Audience: platform owners, operators, AI engineers, and compliance reviewers using a self-hosted Apex installation.

Job: orient quickly, connect a scoped agent, assess what is known versus illustrative, and move from a finding to its evidence without losing scope.

First action: connect an agent or open the incident queue.

Proof and constraints: use sample data only until typed control-plane clients land; label it clearly. Preserve keyboard access, high contrast, server-side redaction, and scoped authority. Treat agent-provided text as untrusted.

Chosen direction: The Operations Map. The memorable moment is an agent-to-evidence topology as the primary object, with the attention queue beside it rather than a dashboard metric wall.

Unresolved: OpenAPI/Protobuf client generation, authenticated session model, live loading/error/denied data contracts, and chart/topology text alternatives.
