import re
import tempfile
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")

README = Path(__file__).resolve().parents[1] / "README.md"


def _safe_replace(text: str, pattern: str, repl: str, flags: int = 0) -> str:
    """Perform a regex substitution and return the new text."""
    return re.sub(pattern, repl, text, flags=flags)


def main() -> None:
    text = README.read_text(encoding="utf-8")
    original = text

    # Replacement map: regex -> replacement.
    # Use whole-word anchors or explicit line matches to avoid accidental changes.
    replacements = {
        r"\bANTHROPIC\b": "GEMINI",
        # Update example model names in simple export lines. This will only change the first matching block.
        r'export BOUNTYOS_MAIN_PROVIDER="gemini"\s*\nexport BOUNTYOS_MAIN_MODEL="[^"]+"\s*\nexport BOUNTYOS_EXPLOIT_MODEL="[^"]+"': (
            'export BOUNTYOS_MAIN_PROVIDER="gemini"\nexport BOUNTYOS_MAIN_MODEL="gemini-2.5-flash"\nexport BOUNTYOS_EXPLOIT_MODEL="gemini-2.5-pro"'
        ),
    }

    for pat, repl in replacements.items():
        text = _safe_replace(text, pat, repl)

    # Prepare debate section (idempotent)
    debate_section = (
        "\n## Collaborative Debate Engine\n\n"
        "The Debate Engine reviews high/critical findings before reporting. It runs a Skeptic → "
        "Proponent → Verdict flow and stores a DebateRecord for each debated finding. "
        "The engine is Gemini/Vertex provider compatible and disabled by default.\n\n"
        "Environment variables:\n\n"
        "```bash\n"
        "export BOUNTYOS_DEBATE_ENABLED=true\n"
        "export BOUNTYOS_DEBATE_MODEL=gemini-2.5-flash\n"
        "export BOUNTYOS_DEBATE_TIMEOUT_SECONDS=60\n"
        "export BOUNTYOS_DEBATE_MAX_TOKENS=1500\n"
        "```\n\n"
        "API examples:\n\n"
        "```bash\n"
        "curl -X POST http://localhost:8000/api/v1/debate/findings/FINDING_ID/run\n"
        "curl -X POST http://localhost:8000/api/v1/debate/scans/SCAN_ID/run\n"
        "```\n"
    )

    if "## Collaborative Debate Engine" not in text:
        # Prefer to insert after a known anchor if present
        anchors = ["## Architecture", "## Getting Started", "## Installation"]
        insert_pos = -1
        for a in anchors:
            idx = text.find(a)
            if idx != -1:
                # Insert after the end of the heading block (find next H2 or end of doc)
                next_h2 = text.find("\n## ", idx + len(a))
                insert_pos = next_h2 if next_h2 != -1 else len(text)
                logging.info(f"Inserting debate section after anchor: '{a}'")
                break

        if insert_pos == -1:
            # Fallback: append at end
            logging.info("Appending debate section at end of README")
            text = text.rstrip() + "\n\n" + debate_section
        else:
            text = text[:insert_pos] + "\n" + debate_section + text[insert_pos:]

    # Only write if there's a change
    if text != original:
        # Atomic write using tempfile in same directory as README
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=README.name + ".", suffix=".tmp", dir=str(README.parent))
            with open(fd, "w", encoding="utf-8") as f:
                f.write(text)
            Path(tmp).replace(README)
            logging.info(f"Updated {README}")
        except Exception as e:
            logging.error(f"Failed to update README: {e}")
            if tmp:
                try:
                    Path(tmp).unlink()
                except Exception:
                    pass
            raise
    else:
        logging.info("No changes to README")


if __name__ == "__main__":
    main()
