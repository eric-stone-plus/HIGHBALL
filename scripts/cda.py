#!/usr/bin/env python3
"""
KOZO · CDA — Cross-Detection Asymmetry (Reference Implementation)

Part of HIGHBALL: https://github.com/eric-stone-plus/HIGHBALL
KOZO (小僧) — attention quality measurement layer.

Computes CDA[A, B]: the degree to which agent B detects errors in agent A's
analysis that A's own self-audit missed.

CDA[A, B] = |errors_of_A_found_by_B| / |errors_of_A|
           - |errors_of_B_found_by_A| / |errors_of_B|

Key property: CDA requires NO ground truth. It only observes relative detection
rates between agent pairs — "did B find something A claimed didn't exist?"

Usage:
  python3 cda.py --a hm_round1.md --b omp_round1.md
  python3 cda.py --debate-dir /tmp/quinte-audit/
  python3 cda.py --debate-dir . --matrix  # all agent pairs

Output:
  JSON with per-pair CDA and supporting evidence.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from itertools import combinations


AGENT_FILES = {
    "hm": "hermes_round1.md",
    "cc": "claude_round1.md",
    "cw": "codewhale_round1.md",
    "omp": "omp_round1.md",
    "rx": "reasonix_round2.md",
}


def extract_claims(filepath):
    """
    Extract claims/assertions from an agent's output.
    Heuristic: lines starting with bullet points, numbered items,
    or containing '→' (error found) or 'claim' keywords.
    Returns list of (line_number, text).
    """
    claims = []
    if not os.path.exists(filepath):
        return claims

    with open(filepath) as f:
        lines = f.readlines()

    claim_patterns = [
        re.compile(r'^[-*]\s+'),           # bullet points
        re.compile(r'^\d+\.\s+'),          # numbered items
        re.compile(r'^\|\s*.*\|\s*.*\|'),  # table rows (skip headers)
    ]

    error_pattern = re.compile(
        r'(error|mistake|missing|incorrect|wrong|false|fails|'
        r'overlook|miss|gap|漏洞|遗漏|错误|不一致)',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue

        is_claim = any(p.match(stripped) for p in claim_patterns)
        is_error = bool(error_pattern.search(stripped))

        if is_claim or is_error:
            claims.append({
                "line": i,
                "text": stripped[:200],
                "is_error_flag": is_error,
            })

    return claims


def find_cross_detections(agent_a, agent_b, claims_a, claims_b):
    """
    Find errors in A's output that B's output references.
    This is a heuristic: we check if B's output mentions any of the same
    topics/file paths that A's errors relate to, but disagrees with A's
    conclusion.
    """
    # Extract key terms from A's error claims
    a_error_terms = set()
    for c in claims_a:
        if c["is_error_flag"]:
            # Extract file paths, identifiers
            terms = re.findall(r'(/[\w/.-]+|`[^`]+`|"[^"]+")', c["text"])
            a_error_terms.update(terms)

    # Count how many of A's error terms appear in B's output
    b_text = " ".join(c["text"] for c in claims_b)
    found = [t for t in a_error_terms if t in b_text]

    return {
        "a_errors": len([c for c in claims_a if c["is_error_flag"]]),
        "a_error_terms_in_b": len(found),
        "terms": found[:10],  # first 10 for evidence
    }


def compute_cda_matrix(debate_dir):
    """Compute CDA for all agent pairs in a debate directory."""
    agents = {}
    claims = {}

    for agent, filename in AGENT_FILES.items():
        path = os.path.join(debate_dir, filename)
        if os.path.exists(path):
            agents[agent] = path
            claims[agent] = extract_claims(path)

    results = {}
    for a, b in combinations(agents.keys(), 2):
        cross = find_cross_detections(a, b, claims[a], claims[b])
        cross_rev = find_cross_detections(b, a, claims[b], claims[a])

        a_errors = cross["a_errors"]
        b_errors = cross_rev["a_errors"]

        if a_errors == 0 and b_errors == 0:
            cda = 0.0
        elif a_errors == 0:
            cda = -cross_rev["a_error_terms_in_b"] / b_errors if b_errors else 0
        elif b_errors == 0:
            cda = cross["a_error_terms_in_b"] / a_errors
        else:
            cda = (cross["a_error_terms_in_b"] / a_errors
                   - cross_rev["a_error_terms_in_b"] / b_errors)

        results[f"{a}↔{b}"] = {
            "cda": round(cda, 3),
            "direction": (
                f"{b}→{a}" if cda > 0 else f"{a}→{b}" if cda < 0 else "symmetric"
            ),
            f"{a}_errors": a_errors,
            f"{b}_errors": b_errors,
            f"{b}_found_in_{a}": cross["a_error_terms_in_b"],
            f"{a}_found_in_{b}": cross_rev["a_error_terms_in_b"],
        }

    return results


def main():
    parser = argparse.ArgumentParser(description="KOZO CDA — Cross-Detection Asymmetry")
    parser.add_argument("--a", help="Agent A output file")
    parser.add_argument("--b", help="Agent B output file")
    parser.add_argument("--debate-dir", help="QUINTE debate directory")
    parser.add_argument("--matrix", action="store_true",
                        help="Compute CDA for all agent pairs")
    args = parser.parse_args()

    if args.debate_dir:
        results = compute_cda_matrix(args.debate_dir)
    elif args.a and args.b:
        claims_a = extract_claims(args.a)
        claims_b = extract_claims(args.b)
        cross = find_cross_detections("A", "B", claims_a, claims_b)
        cross_rev = find_cross_detections("B", "A", claims_b, claims_a)
        results = {"A↔B": {"cross": cross, "cross_rev": cross_rev}}
    else:
        parser.error("Need --debate-dir or (--a + --b)")

    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
