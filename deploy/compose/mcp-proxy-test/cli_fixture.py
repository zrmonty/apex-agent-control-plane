"""Fixed CLI fixture; accepts typed scalar input and emits bounded JSON."""

import json
import sys


value = sys.argv[1] if len(sys.argv) == 2 else "fixture"
print(json.dumps({"value": value, "source": "fixed-cli-fixture"}, separators=(",", ":")))
