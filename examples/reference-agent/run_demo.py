"""Run a gold-standard Phase 0 reference agent locally."""

import json
from pathlib import Path

from apex_sdk import (
    BoundedObserver,
    GOLD_STANDARD_CONTROLS,
    JsonlSink,
    ReferenceReasonActLoop,
    TEMPLATE_VERSION,
    assess_agent_template,
)


def main() -> None:
    local_dir = Path(".local")
    if local_dir.exists() and local_dir.is_symlink():
        raise RuntimeError("Refusing to write the demo trace through a symbolic-link .local directory")
    local_dir.mkdir(exist_ok=True)
    output_dir = local_dir / "apex"
    if output_dir.exists() and output_dir.is_symlink():
        raise RuntimeError("Refusing to write the demo trace through a symbolic-link output directory")
    output_dir.mkdir(exist_ok=True)
    output_dir = output_dir.resolve(strict=True)
    output_path = output_dir / "events.jsonl"
    manifest = {
        "template_version": TEMPLATE_VERSION,
        "agent_code": "home-demo",
        "controls": {control: True for control in GOLD_STANDARD_CONTROLS},
    }
    assessment = assess_agent_template(manifest)
    if not assessment.compliant:
        finding = assessment.security_finding()
        raise RuntimeError(f"Agent template is noncompliant: {finding}")
    (output_dir / "agent-template.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sink = JsonlSink(output_path, base_dir=output_dir)
    observer = BoundedObserver(sink, capacity=256)
    try:
        loop = ReferenceReasonActLoop(
            observer,
            agent_id="home-reference-agent",
            scope={"workspace_id": "local", "namespace_id": "demo", "agent_group_ids": []},
            version={"agent_code": "home-demo", "prompt": "home-demo", "model": "reference"},
        )
        events = loop.run(
            "Demonstrate a safe local agent trace.",
            tool=lambda value: f"tool-result:{value}",
            child_agent_id="home-child-agent",
        )
        observer.close(timeout=2)
    finally:
        observer.close(timeout=2)
    print(f"Template score: {assessment.score:.2f} ({assessment.template_version})")
    print(f"Wrote {len(events)} events to {output_path}")
    print("Observe them with: Get-Content .local/apex/events.jsonl -Wait")


if __name__ == "__main__":
    main()
