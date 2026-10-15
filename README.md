# Firewall Rule Auditor

An AI-assisted auditor for **iptables** firewall rules. It finds shadowed, overly permissive, redundant, and unused rules, then uses a **local LLM (Ollama)** to explain each finding in plain English with a recommended fix.

No cloud services, no API keys, no cost: rule data never leaves your machine.

## Why this design

> **Code finds the problems. The AI only explains them.**

Questions like "is `10.66.0.5` inside `10.0.0.0/8`?" or "does rule 3 make rule 5 unreachable?" are exact set math. Python's `ipaddress` module answers them correctly every time; LLMs sometimes don't. So detection is deterministic, and the LLM is used only for what it's good at: turning a technical finding into a clear explanation and suggested fix.

The AI layer is also constrained:
- It receives only the findings, never asked to discover new ones
- Output is forced to JSON and validated
- Any explanation whose ID doesn't match a real finding is discarded

## What it detects

| Check | Severity | Example |
|---|---|---|
| Allow-all rule | Critical | `-A FORWARD -j ACCEPT` |
| Default-allow policy | High | `:INPUT ACCEPT` |
| Shadowed conflicting rule | High | A `DROP` placed below a broader `ACCEPT`, so it never fires |
| Sensitive service exposed to any source | High | RDP, SSH, SMB, databases open to `0.0.0.0/0` |
| All ports open to a source range | Medium | Partner network can reach every port |
| Redundant rule | Low | Fully covered by an earlier rule with the same action |
| Unused rule | Low | Hit counter is `0` |

## Example

Running it on the included `sample_rules.txt` (12 rules with deliberate problems):

```
12 rules, 13 findings (1 critical, 4 high, 1 medium, 7 low). Report: audit_report.md
```

One of the findings it catches:

```
F003 · HIGH · shadowed_conflict
-A INPUT -s 10.66.0.5/32 -p tcp --dport 22 --comment "block compromised host" -j DROP

Never reached: line 8 matches all of this traffic first and applies ACCEPT,
so this rule's DROP never takes effect.
Caused by: -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 --comment "SSH from corp" -j ACCEPT
```

Someone believed the compromised host was blocked; it wasn't. Moving the `DROP` above the `ACCEPT` fixes it, and re-running the audit confirms the finding is gone.

See [`example_report.md`](example_report.md) for the full report.

## Quick start

Requires **Python 3.10+**. No extra packages needed.

```bash
# 1. Checks only (no AI)
python fw_auditor.py sample_rules.txt --no-llm

# 2. Checks + free local AI explanations
#    Install Ollama from https://ollama.com, then:
ollama pull llama3.2
python fw_auditor.py sample_rules.txt
```

The report is written to `audit_report.md`. Add `--json findings.json` for machine-readable output.

### Auditing real rules

On a Linux host:

```bash
sudo iptables-save -c > rules.txt     # -c includes hit counters for the "unused" check
python fw_auditor.py rules.txt
```

### Options

| Option | Purpose |
|---|---|
| `--no-llm` | Run detection only |
| `--model qwen2.5:7b` | Use a different Ollama model |
| `--provider anthropic` | Use the Claude API instead (requires `ANTHROPIC_API_KEY`) |
| `--out FILE` | Report path (default `audit_report.md`) |
| `--json FILE` | Also write findings as JSON |

## How it works

```
iptables-save output
   │
   ▼
Parser ──► rule objects (source, destination, protocol, ports, state, action)
   │
   ▼
Checks ──► shadowing · permissiveness · unused · default policy
   │
   ▼
Ollama (localhost) ──► plain-English explanation, risk, recommended fix
   │
   ▼
audit_report.md / findings.json
```

## Limitations

- iptables `filter` table only (Palo Alto / FortiGate parsers are planned)
- Unknown match modules and negated conditions are treated conservatively, so the tool may miss some shadowing rather than report false positives
- Hit counters reset on reboot or reload; verify "unused" findings over a long window
- Small local models can phrase explanations imperfectly; always review recommendations before applying them

## Roadmap

- [ ] Palo Alto and FortiGate config parsers
- [ ] `nat` and `mangle` table support
- [ ] HTML report
- [ ] Unit tests and CI

## Security note

Ollama listens only on `localhost:11434` by default. Keep it that way: don't set `OLLAMA_HOST=0.0.0.0`, especially on shared or public networks.
