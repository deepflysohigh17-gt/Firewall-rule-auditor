#!/usr/bin/env python3
"""
Firewall Rule Auditor (iptables edition)

Design principle: CODE finds the problems, the LLM only EXPLAINS them.
LLMs are unreliable at set math like "does subnet A contain subnet B?",
so shadowing / permissiveness / unused checks are deterministic Python.
The LLM turns each finding into plain English, a risk statement and a fix.

Usage:
    sudo iptables-save -c > rules.txt          # -c includes hit counters
    python fw_auditor.py rules.txt --no-llm    # checks only
    python fw_auditor.py rules.txt             # checks + FREE local AI (Ollama)
    python fw_auditor.py rules.txt --model qwen2.5:7b    # pick another Ollama model
    python fw_auditor.py rules.txt --provider anthropic  # optional paid Claude API
    python fw_auditor.py rules.txt --json findings.json
"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

TERMINAL = {"ACCEPT", "DROP", "REJECT"}
SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "MS-RPC",
    139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
# Match modules whose options we understand natively; anything else goes in `extras`.
KNOWN_MODULES = {"tcp", "udp", "multiport", "state", "conntrack", "comment"}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    line_no: int
    raw: str
    table: str
    chain: str = ""
    target: str = ""
    proto: str | None = None          # None = any
    src: object = None                # ip_network or None (= any)
    dst: object = None
    in_if: str | None = None
    out_if: str | None = None
    sports: list | None = None        # list of (lo, hi) or None (= any)
    dports: list | None = None
    states: frozenset | None = None
    extras: frozenset = frozenset()   # unparsed/unknown conditions (kept conservative)
    packets: int | None = None        # hit counter, if exported with -c
    comment: str = ""

    def short(self) -> str:
        return f"line {self.line_no}: {self.raw}"


@dataclass
class Policy:
    table: str
    chain: str
    action: str
    line_no: int


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def parse_ports(spec: str) -> list:
    out = []
    for part in spec.split(","):
        if ":" in part:
            lo, hi = part.split(":", 1)
            out.append((int(lo or 0), int(hi or 65535)))
        else:
            p = int(part)
            out.append((p, p))
    return out


def parse_net(spec: str):
    net = ipaddress.ip_network(spec, strict=False)
    return None if net.prefixlen == 0 else net


def parse_rule(line: str, line_no: int, table: str) -> Rule:
    packets = None
    m = re.match(r"^\[(\d+):(\d+)\]\s+(.*)$", line)
    if m:
        packets, line = int(m.group(1)), m.group(3)

    r = Rule(line_no=line_no, raw=line, table=table, packets=packets)
    tokens = shlex.split(line)
    extras: list[str] = []
    negate = False
    i = 0
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t == "!":
            negate = True
            i += 1
            continue
        if t in ("-A", "--append"):
            r.chain = nxt
            i += 2
            continue
        if t in ("-j", "--jump", "-g", "--goto"):
            r.target = nxt
            break  # iptables-save puts the target last; the rest are target options
        if negate:
            # Negated conditions are rare and tricky; keep them as opaque extras.
            extras.append(f"! {t} {nxt}")
            negate = False
            i += 2
            continue
        try:
            if t in ("-p", "--protocol"):
                r.proto = None if nxt.lower() == "all" else nxt.lower()
            elif t in ("-s", "--source"):
                r.src = parse_net(nxt)
            elif t in ("-d", "--destination"):
                r.dst = parse_net(nxt)
            elif t in ("-i", "--in-interface"):
                r.in_if = nxt
            elif t in ("-o", "--out-interface"):
                r.out_if = nxt
            elif t in ("--dport", "--destination-port", "--dports", "--destination-ports"):
                r.dports = parse_ports(nxt)
            elif t in ("--sport", "--source-port", "--sports", "--source-ports"):
                r.sports = parse_ports(nxt)
            elif t in ("--state", "--ctstate"):
                r.states = frozenset(s.upper() for s in nxt.split(","))
            elif t == "--comment":
                r.comment = nxt
            elif t in ("-m", "--match"):
                if nxt not in KNOWN_MODULES:
                    extras.append(f"-m {nxt}")
            elif nxt and not nxt.startswith("-"):
                extras.append(f"{t} {nxt}")
            else:
                extras.append(t)
                i += 1
                continue
        except ValueError:
            # e.g. a named service port like "ssh": treat as an unknown condition
            extras.append(f"{t} {nxt}")
        i += 2
    r.extras = frozenset(extras)
    return r


def parse_iptables_save(text: str):
    rules, policies = [], []
    table = "filter"
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line == "COMMIT":
            continue
        if line.startswith("*"):
            table = line[1:]
        elif line.startswith(":"):
            parts = line[1:].split()
            policies.append(Policy(table, parts[0], parts[1], n))
        elif "-A " in line:
            rules.append(parse_rule(line, n, table))
    return rules, policies


# --------------------------------------------------------------------------- #
# Coverage logic: does rule A match every packet rule B matches?
# --------------------------------------------------------------------------- #
def _any_or_eq(a, b):
    return a is None or a == b


def _net_covers(a, b):
    if a is None:
        return True
    if b is None:
        return False
    return a.version == b.version and b.subnet_of(a)


def _ports_cover(a, b):
    if a is None:
        return True
    if b is None:
        return False
    return all(any(alo <= lo and hi <= ahi for alo, ahi in a) for lo, hi in b)


def _states_cover(a, b):
    if a is None:
        return True
    if b is None:
        return False
    return b <= a


def covers(a: Rule, b: Rule) -> bool:
    return (
        a.table == b.table
        and a.chain == b.chain
        and _any_or_eq(a.proto, b.proto)
        and _net_covers(a.src, b.src)
        and _net_covers(a.dst, b.dst)
        and _any_or_eq(a.in_if, b.in_if)
        and _any_or_eq(a.out_if, b.out_if)
        and _ports_cover(a.sports, b.sports)
        and _ports_cover(a.dports, b.dports)
        and _states_cover(a.states, b.states)
        and a.extras <= b.extras  # A may not have extra restrictions B lacks
    )


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _finding(check, severity, rule, detail, related=None):
    return {
        "check": check,
        "severity": severity,
        "table": rule.table,
        "chain": rule.chain,
        "rule_line": rule.line_no,
        "rule": rule.raw,
        "related_rule": related.short() if related else None,
        "detail": detail,
    }


def check_shadowed(rules):
    out = []
    for idx, b in enumerate(rules):
        for a in rules[:idx]:
            if a.target in TERMINAL and covers(a, b):
                if a.target == b.target:
                    out.append(_finding(
                        "redundant", "low", b,
                        f"Never reached: line {a.line_no} already matches all of this "
                        f"traffic with the same action ({a.target}).", a))
                else:
                    out.append(_finding(
                        "shadowed_conflict", "high", b,
                        f"Never reached: line {a.line_no} matches all of this traffic first "
                        f"and applies {a.target}, so this rule's {b.target} never takes effect.", a))
                break
    return out


def _established_only(r):
    return r.states is not None and r.states <= {"ESTABLISHED", "RELATED"}


def check_permissive(rules):
    out = []
    for r in rules:
        if r.target != "ACCEPT" or r.in_if == "lo" or _established_only(r):
            continue
        any_src, any_dst = r.src is None, r.dst is None
        any_port = r.dports is None
        if any_src and any_dst and any_port and r.proto is None and not r.extras:
            out.append(_finding("any_any", "critical", r,
                                "Accepts all traffic: any source, any destination, any protocol, any port."))
            continue
        if any_src and any_port and not r.extras:
            out.append(_finding("any_source_all_ports", "high", r,
                                f"Accepts {r.proto or 'all protocols'} on every port from any source."))
            continue
        if any_src and r.dports:
            exposed = sorted({name for port, name in SENSITIVE_PORTS.items()
                              if any(lo <= port <= hi for lo, hi in r.dports)})
            if exposed:
                out.append(_finding("sensitive_service_exposed", "high", r,
                                    f"{', '.join(exposed)} reachable from any source address."))
                continue
        if not any_src and any_port and r.proto is None and not r.extras:
            out.append(_finding("all_ports_from_source", "medium", r,
                                f"Accepts every protocol and port from {r.src}; "
                                "consider limiting to the services actually needed."))
    return out


def check_unused(rules):
    return [_finding("unused", "low", r,
                     "Hit counter is 0. Verify over a long window (counters reset on "
                     "reboot/reload) before removing.")
            for r in rules if r.packets == 0]


def check_policies(policies):
    out = []
    for p in policies:
        if p.table == "filter" and p.chain in ("INPUT", "FORWARD") and p.action == "ACCEPT":
            fake = Rule(line_no=p.line_no, raw=f":{p.chain} {p.action}", table=p.table, chain=p.chain)
            out.append(_finding("default_allow_policy", "high", fake,
                                f"Default policy for {p.chain} is ACCEPT: anything not explicitly "
                                "blocked is allowed (default-allow instead of default-deny)."))
    return out


def run_checks(rules, policies):
    findings = (check_policies(policies) + check_permissive(rules)
                + check_shadowed(rules) + check_unused(rules))
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["rule_line"]))
    for n, f in enumerate(findings, start=1):
        f["id"] = f"F{n:03d}"
    return findings


# --------------------------------------------------------------------------- #
# LLM explanation layer (structured output)
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """You are a senior network security engineer explaining firewall audit findings
to a mixed audience of engineers and managers.

You receive findings that were produced by deterministic analysis. Treat them as correct.
Do NOT change severities, do NOT invent new findings, do NOT speculate about rules you were not shown.

For every finding return an object with exactly these keys:
  "id":             the finding id, unchanged
  "rule_in_plain_english": one sentence describing what the rule does, no jargon
  "why_it_matters": one or two sentences on the concrete risk or operational impact
  "recommendation": a specific fix; include a corrected iptables command when one is obvious

Respond with ONLY a JSON object of the form {"findings": [ ...objects... ]}.
No prose, no markdown fences."""

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODELS = {"ollama": "llama3.2", "anthropic": "claude-sonnet-5-5"}


def _extract_json(text: str):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    data = json.loads(text)
    if isinstance(data, dict):  # {"findings": [...]} or a single finding object
        data = data.get("findings", [data])
    return data if isinstance(data, list) else []


def _call_ollama(model, user_content):
    body = json.dumps({
        "model": model,
        "stream": False,
        "format": "json",               # forces valid JSON output
        "options": {"temperature": 0.2},
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user_content}],
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            return json.loads(resp.read())["message"]["content"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit(f"Ollama doesn't have the model '{model}' yet. Run:  ollama pull {model}")
        raise
    except urllib.error.URLError:
        sys.exit("Can't reach Ollama at " + OLLAMA_URL + ". Install it from ollama.com, "
                 "make sure the Ollama app is running, then try again (or use --no-llm).")


def _call_anthropic(model, user_content):
    try:
        import anthropic
    except ImportError:
        sys.exit("The anthropic package is missing. Run: pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("Set ANTHROPIC_API_KEY, or use the free default (--provider ollama).")
    resp = anthropic.Anthropic().messages.create(
        model=model, max_tokens=4000, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}])
    return "".join(b.text for b in resp.content if b.type == "text")


def explain_with_llm(findings, provider, model):
    # Small local models do better with a few findings at a time.
    batch_size = 4 if provider == "ollama" else 15
    call = _call_ollama if provider == "ollama" else _call_anthropic
    explanations = {}
    for start in range(0, len(findings), batch_size):
        batch = findings[start:start + batch_size]
        print(f"  Explaining findings {start + 1}-{start + len(batch)} of {len(findings)} "
              f"with {model}...", flush=True)
        payload = [{k: f[k] for k in ("id", "check", "severity", "chain", "rule",
                                      "related_rule", "detail")} for f in batch]
        text = call(model, json.dumps(payload, indent=2))
        try:
            items = _extract_json(text)
        except json.JSONDecodeError:
            print(f"  Warning: could not parse AI output for this batch; skipping it.",
                  file=sys.stderr)
            continue
        expected = {f["id"] for f in batch}
        for item in items:
            if isinstance(item, dict) and item.get("id") in expected:  # ignore invented ids
                explanations[item["id"]] = item
    for f in findings:
        f["explanation"] = explanations.get(f["id"])
    return findings


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def render_markdown(findings, source_name, rule_count):
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
    lines = [f"# Firewall Audit: {source_name}", "",
             f"Rules analyzed: **{rule_count}**  |  Findings: **{len(findings)}**", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {s.capitalize()} | {c} |" for s, c in counts.items() if c]
    lines.append("")
    for f in findings:
        lines += [f"## {f['id']} · {f['severity'].upper()} · {f['check']}", "",
                  f"**Chain:** {f['table']}/{f['chain']}  ·  **Line:** {f['rule_line']}", "",
                  "```", f["rule"], "```", "",
                  f"**Finding:** {f['detail']}"]
        if f["related_rule"]:
            lines.append(f"\n**Caused by:** `{f['related_rule']}`")
        exp = f.get("explanation")
        if exp:
            lines += ["", f"**In plain English:** {exp.get('rule_in_plain_english', '')}",
                      "", f"**Why it matters:** {exp.get('why_it_matters', '')}",
                      "", f"**Recommendation:** {exp.get('recommendation', '')}"]
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Audit iptables rules and explain findings.")
    ap.add_argument("rules_file", help="output of `iptables-save -c`")
    ap.add_argument("--no-llm", action="store_true", help="run checks only")
    ap.add_argument("--provider", choices=["ollama", "anthropic"], default="ollama",
                    help="ollama = free local AI (default); anthropic = paid Claude API")
    ap.add_argument("--model", help="model name (default: llama3.2 for Ollama)")
    ap.add_argument("--out", default="audit_report.md", help="markdown report path")
    ap.add_argument("--json", help="also write findings as JSON to this path")
    args = ap.parse_args()

    with open(args.rules_file) as fh:
        rules, policies = parse_iptables_save(fh.read())
    findings = run_checks(rules, policies)
    if not args.no_llm and findings:
        model = args.model or DEFAULT_MODELS[args.provider]
        findings = explain_with_llm(findings, args.provider, model)

    report = render_markdown(findings, os.path.basename(args.rules_file), len(rules))
    with open(args.out, "w") as fh:
        fh.write(report)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(findings, fh, indent=2)

    summary = ", ".join(f"{sum(f['severity'] == s for f in findings)} {s}"
                        for s in SEVERITY_ORDER if any(f["severity"] == s for f in findings))
    print(f"{len(rules)} rules, {len(findings)} findings ({summary or 'none'}). Report: {args.out}")


if __name__ == "__main__":
    main()
