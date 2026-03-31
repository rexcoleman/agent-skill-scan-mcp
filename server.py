#!/usr/bin/env python3
"""MCP server for agent skill file security scanning.

Wraps agent-skill-scanner (PyPI) as an MCP server for Claude Code.
Scans OpenClaw SKILL.md and MCP tool definition files for 22 security
rules across prompt injection, capability escalation, data exfiltration,
encoded payloads, and composition risks.
"""

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Import scanner engine
try:
    from skill_scanner.parser import parse_skill_file
    from skill_scanner.engine import DetectionEngine
    from skill_scanner.rules import load_rules_from_yaml
    from skill_scanner.cli import find_skill_files

    # Locate rules directory (inside installed package)
    RULES_DIR = Path(__file__).parent / "skill_scanner" / "rules"
    if not RULES_DIR.exists():
        # Fallback: installed package location
        import skill_scanner
        RULES_DIR = Path(skill_scanner.__file__).parent / "rules"
except ImportError:
    print(
        "Error: agent-skill-scanner not installed. Run: pip install agent-skill-scanner",
        file=sys.stderr,
    )
    sys.exit(1)


mcp = FastMCP(
    "agent-skill-scanner",
    instructions="Scan agent skill files for security vulnerabilities. "
    "22 rules for OpenClaw SKILL.md and MCP tool definitions.",
)


def _get_engine() -> DetectionEngine:
    """Create and configure the detection engine."""
    engine = DetectionEngine()
    rules = load_rules_from_yaml(RULES_DIR)
    engine.load_rules(rules)
    return engine


def _format_findings(results: list) -> str:
    """Format scan results as structured text for Claude."""
    if not results:
        return "No skill files found at the specified path."

    total_findings = sum(r.finding_count for r in results)
    if total_findings == 0:
        return f"Scanned {len(results)} skill files. No security findings detected."

    lines = []
    for r in results:
        if r.findings:
            lines.append(f"### {r.skill_name} ({len(r.findings)} findings)")
            for f in r.findings:
                lines.append(
                    f"- **[{f.severity.value}]** {f.title} ({f.rule_id})\n"
                    f"  {f.description}\n"
                    f"  Evidence: `{f.evidence[:100]}`"
                )
            lines.append("")

    summary = (
        f"**Summary:** Scanned {len(results)} skill files, "
        f"found {total_findings} security issues."
    )
    lines.insert(0, summary)
    lines.insert(1, "")
    return "\n".join(lines)


@mcp.tool()
def scan_skill_file(file_path: str) -> str:
    """Scan a single agent skill file for security vulnerabilities.

    Analyzes an OpenClaw SKILL.md or MCP tool definition file against
    22 detection rules covering prompt injection, capability escalation,
    data exfiltration, encoded payloads, and composition risks.

    Args:
        file_path: Path to the skill file to scan.

    Returns:
        Structured findings with severity, rule ID, description, and evidence.
    """
    path = Path(file_path)
    if not path.exists():
        return f"Error: File not found: {file_path}"
    if not path.is_file():
        return f"Error: Not a file: {file_path}"

    engine = _get_engine()
    try:
        skill = parse_skill_file(path)
        result = engine.scan(skill)
    except Exception as e:
        return f"Error scanning {file_path}: {e}"

    if not result.findings:
        return f"No security findings in {path.name}."

    lines = [f"**{path.name}:** {len(result.findings)} findings\n"]
    for f in result.findings:
        lines.append(
            f"- **[{f.severity.value}]** {f.title} ({f.rule_id})\n"
            f"  {f.description}\n"
            f"  Evidence: `{f.evidence[:100]}`"
        )
    return "\n".join(lines)


@mcp.tool()
def scan_directory(directory_path: str) -> str:
    """Scan a directory for agent skill files and check them for security vulnerabilities.

    Recursively finds OpenClaw SKILL.md files and markdown files with
    skill frontmatter (name/description fields), then scans each against
    22 detection rules.

    Args:
        directory_path: Path to the directory to scan.

    Returns:
        Aggregated findings across all discovered skill files.
    """
    path = Path(directory_path)
    if not path.exists():
        return f"Error: Directory not found: {directory_path}"
    if not path.is_dir():
        return f"Error: Not a directory: {directory_path}"

    engine = _get_engine()
    skill_files = find_skill_files(path)

    if not skill_files:
        return f"No agent skill files found in {directory_path}."

    results = []
    for skill_path in skill_files:
        try:
            skill = parse_skill_file(skill_path)
            result = engine.scan(skill)
            results.append(result)
        except Exception:
            continue

    return _format_findings(results)


if __name__ == "__main__":
    mcp.run(transport="stdio")
