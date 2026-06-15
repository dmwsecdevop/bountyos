import os
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"
text = README.read_text(encoding="utf-8")

# Replace Gemini/Vertex mentions with Gemini/Vertex where reasonable
text = text.replace("Gemini/Vertex-powered agents", "Gemini/Vertex-powered agents")
text = text.replace("GEMINI_API_KEY", "GEMINI_API_KEY")
text = text.replace("ANTHROPIC", "GEMINI")
text = text.replace("gemini", "gemini")

# Update model routing example
text = text.replace(
    'export BOUNTYOS_MAIN_PROVIDER="gemini"\nexport BOUNTYOS_MAIN_MODEL="gemini-opus-4-5"\nexport BOUNTYOS_EXPLOIT_MODEL="gemini-opus-4-5"',
    'export BOUNTYOS_MAIN_PROVIDER="gemini"\nexport BOUNTYOS_MAIN_MODEL="gemini-2.5-flash"\nexport BOUNTYOS_EXPLOIT_MODEL="gemini-2.5-pro"'
)

# Add Debate Engine section if not present
if "## Collaborative Debate Engine" not in text:
    debate_section = "\n## Collaborative Debate Engine\n\nThe Debate Engine reviews high/critical findings before reporting. It runs a Skeptic → Proponent → Verdict flow and stores a DebateRecord for each debated finding. The engine is Gemini/Vertex provider compatible and disabled by default.\n\nEnvironment variables:\n\n```
export BOUNTYOS_DEBATE_ENABLED=true\nexport BOUNTYOS_DEBATE_MODEL=gemini-2.5-flash\nexport BOUNTYOS_DEBATE_TIMEOUT_SECONDS=60\nexport BOUNTYOS_DEBATE_MAX_TOKENS=1500\n```\n\nAPI examples:\n\n```
curl -X POST http://localhost:8000/api/v1/debate/findings/FINDING_ID/run\ncurl -X POST http://localhost:8000/api/v1/debate/scans/SCAN_ID/run\n```
\n"
    # insert near top after Architecture section
    insert_at = text.find("## Collaborative Debate Engine")
    if insert_at == -1:
        # append near top after initial setup area
        text = text + debate_section

README.write_text(text, encoding="utf-8")
