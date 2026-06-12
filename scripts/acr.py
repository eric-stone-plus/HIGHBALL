#!/usr/bin/env python3
"""
KOZO · ACR — Attention Compliance Rate (Reference Implementation)

Part of HIGHBALL: https://github.com/eric-stone-plus/HIGHBALL
KOZO (小僧) — attention quality measurement layer.

Computes ACR per agent: |files_read ∩ files_assigned| / |files_assigned|

Usage:
  python3 acr.py --assigned assigned.json --read-log read.log [--agent hm]
  python3 acr.py --debate-dir /tmp/quinte-audit/

Input formats:
  --assigned: JSON array of {agent, files: [path, ...]}
  --read-log:  text file with lines: AGENT:PATH (one per file read)
  --debate-dir: auto-detects hermes_round1.md etc. and checks if agent outputs
                reference the files they were assigned

Output:
  JSON with per-agent ACR, citation rate, and attention span.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict


def parse_assigned(path):
    """Parse assigned files JSON."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return {entry.get("agent", "unknown"): entry.get("files", []) for entry in data}
    return data


def parse_read_log(path):
    """Parse read log: AGENT:FILEPATH per line."""
    reads = defaultdict(set)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            agent, _, filepath = line.partition(":")
            reads[agent.strip()].add(filepath.strip())
    return reads


def detect_from_debate_dir(debate_dir):
    """Auto-detect assigned files and reads from a QUINTE debate directory."""
    assigned = {}
    reads = defaultdict(set)

    agent_files = {
        "hm": "hermes_round1.md",
        "cc": "claude_round1.md",
        "cw": "codewhale_round1.md",
        "omp": "omp_round1.md",
        "rx": "reasonix_round2.md",
    }

    # Assigned: what each agent was supposed to read (from its prompt)
    # In a real implementation this would parse the orchestration prompt.
    # Here we use a heuristic: check which output files exist.
    for agent, filename in agent_files.items():
        path = os.path.join(debate_dir, filename)
        if os.path.exists(path):
            assigned[agent] = [path]

    # Read detection: check which files are cited in agent outputs
    file_pattern = re.compile(r'(/[\w/.-]+\.(?:md|py|sh|yaml|json|toml))')
    for agent, filename in agent_files.items():
        path = os.path.join(debate_dir, filename)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            content = f.read()
        for match in file_pattern.findall(content):
            reads[agent].add(match)

    return assigned, reads


def compute_acr(assigned, reads):
    """Compute ACR per agent."""
    results = {}
    for agent, files in assigned.items():
        assigned_set = set(files)
        read_set = reads.get(agent, set())

        read_assigned = assigned_set & read_set
        compliance = len(read_assigned) / len(assigned_set) if assigned_set else 0

        # Citation rate: did the agent reference the files in its output?
        # (Same as read for now; real impl would distinguish "opened" from "cited")
        citation = compliance

        # Span: total unique files touched
        span = len(read_set)

        results[agent] = {
            "assigned": len(assigned_set),
            "read": len(read_assigned),
            "compliance": round(compliance, 3),
            "citation_rate": round(citation, 3),
            "span": span,
            "unread": sorted(assigned_set - read_set),
        }

    return results


def main():
    parser = argparse.ArgumentParser(description="KOZO ACR — Attention Compliance Rate")
    parser.add_argument("--assigned", help="JSON file mapping agents to assigned files")
    parser.add_argument("--read-log", help="Read log: AGENT:PATH per line")
    parser.add_argument("--debate-dir", help="QUINTE debate directory (auto-detect)")
    parser.add_argument("--agent", help="Filter to single agent")
    args = parser.parse_args()

    if args.debate_dir:
        assigned, reads = detect_from_debate_dir(args.debate_dir)
    elif args.assigned and args.read_log:
        assigned = parse_assigned(args.assigned)
        reads = parse_read_log(args.read_log)
    else:
        parser.error("Need --debate-dir or (--assigned + --read-log)")

    results = compute_acr(assigned, reads)

    if args.agent:
        results = {args.agent: results.get(args.agent, {})}

    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
