#!/usr/bin/env python3
import json, urllib.request, pathlib

BASE = "https://bountyos-wyr2fxj3ta-el.a.run.app"
data = json.load(urllib.request.urlopen(BASE + "/api/v1/runners/capabilities"))

runner = data["online"][0]
tools = runner["tools"]

spec = {}
for name, info in tools.items():
    binary = info.get("binary") or name
    spec[name] = {
        "binary": binary,
        "phase": "util",
        "category": "tool",
        "passive_safe": False,
        "version_flag": "--version"
    }

out = pathlib.Path("runner/tool_specs.json")
out.write_text(json.dumps(spec, indent=2) + "\n")
print("generated tools:", len(spec))
print("saved:", out)
