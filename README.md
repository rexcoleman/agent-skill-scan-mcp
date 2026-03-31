# agent-skill-scanner MCP Server

> Last updated: 2026-03-31

Scan OpenClaw SKILL.md and Model Context Protocol (MCP) tool definition files for security vulnerabilities — directly from Claude Code.

22 detection rules across prompt injection, capability escalation, data exfiltration, encoded payloads, and composition risks. This is the only scanner targeting agent skill file formats specifically. Generic Static Application Security Testing (SAST) tools produce zero detections on these formats.

## Install

Requires Python 3.10+ and the scanner engine:

```bash
pip install agent-skill-scanner
```

## Configure in Claude Code

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "agent-skill-scanner": {
      "command": "python3",
      "args": ["/path/to/agent-skill-scan-mcp/server.py"]
    }
  }
}
```

Replace `/path/to/` with the actual path where you cloned this repo.

## Tools

### `scan_skill_file`

Scan a single skill file for security vulnerabilities.

```
scan_skill_file(file_path="/path/to/SKILL.md")
```

Returns findings with severity, rule ID, description, and evidence.

### `scan_directory`

Recursively find and scan all agent skill files in a directory.

```
scan_directory(directory_path="/path/to/skills/")
```

Returns aggregated findings across all discovered skill files.

## What it detects

22 rules across 5 categories:

| Category | Examples |
|----------|---------|
| **Prompt injection** | System prompt override, role hijacking, instruction injection |
| **Capability escalation** | Privilege escalation, shell spawning, persistence mechanisms |
| **Data exfiltration** | Credential access, environment variable reads, outbound transfer |
| **Encoded payloads** | Base64 commands, hex payloads, obfuscated strings |
| **Composition risks** | Unrestricted tool chaining, cross-skill data flow, trust violations |

## Differentiator

This scanner targets **OpenClaw SKILL.md and MCP tool definition formats** — markdown-embedded code and YAML skill configurations that generic SAST tools (semgrep, CodeQL) miss entirely. If you're scanning general Python/JavaScript code, use [Snyk](https://github.com/snyk/agent-scan) or [semgrep](https://semgrep.dev). If you're scanning agent skill files, this is the only tool that covers the format.

## Trust & Security

This server runs locally via stdio. No network calls beyond the initial `pip install`. No data collection. No telemetry.

Source is fully auditable in this repo. The scanner engine source is at [github.com/rexcoleman/agent-skill-scanner](https://github.com/rexcoleman/agent-skill-scanner).

## Limitations

- Pattern-based detection only — no semantic analysis
- Designed for OpenClaw SKILL.md and MCP tool definitions
- Rules cover known attack patterns from published research, not zero-days

## Links

- **Scanner (PyPI):** [agent-skill-scanner](https://pypi.org/project/agent-skill-scanner/)
- **GitHub Action:** [agent-skill-scan-action](https://github.com/rexcoleman/agent-skill-scan-action)
- **Research:** [rexcoleman.dev](https://rexcoleman.dev)

## License

[MIT](LICENSE)
