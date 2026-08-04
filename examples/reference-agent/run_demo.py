"""Run a gold-standard Phase 0 reference agent locally."""

import json
from pathlib import Path

from apex_sdk import Apex


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

    apex = Apex.connect(agent_code="home-demo", trace_dir=output_dir)
    (output_dir / "agent-template.json").write_text(
        json.dumps(apex.preflight.template.event_data(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "agent-bundle.json").write_text(
        json.dumps(apex.bundle, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with apex.run("home-demo") as loop:
        events = loop.run(
            "Demonstrate a safe local agent trace.",
            tool=lambda value: f"tool-result:{value}",
            child_agent_id="home-child-agent",
        )
    print(
        f"Preflight: {apex.preflight.status} "
        f"(template score {apex.preflight.template.score:.2f}, profile {apex.preflight.profile})"
    )
    print(f"Wrote {len(events)} events to {apex.trace_path}")
    print("Observe them with: Get-Content .local/apex/events.jsonl -Wait")


if __name__ == "__main__":
    main()
