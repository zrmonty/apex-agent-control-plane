"""Static assertions for the managed proxy Compose security posture."""

from pathlib import Path
import subprocess
import sys


def main() -> int:
    compose = Path(__file__).parents[1] / "compose.mcp-proxy.yaml"
    text = compose.read_text(encoding="utf-8")
    required = ("user: \"10001:10001\"", "read_only: true", "no-new-privileges:true", "cap_drop: [ALL]", "mcp-proxy-egress")
    missing = [value for value in required if value not in text]
    if missing:
        print("missing managed proxy controls: " + ", ".join(missing), file=sys.stderr)
        return 1
    if "docker.sock" in text or "/var/run/docker" in text or "privileged: true" in text:
        print("runtime socket or privileged mode is forbidden", file=sys.stderr)
        return 1
    subprocess.run([sys.executable, "-m", "json.tool", str(compose.with_name("mcp-proxy-test") / "revision-config.json")], check=True, stdout=subprocess.DEVNULL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
