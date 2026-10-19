#!/usr/bin/env python3
"""Validate a findings.json against the contract in references/findings-schema.md.

Zero dependencies (Python 3 standard library only). Usage:

    python3 -I validate_findings.py findings.json

Exit 0 if every record is valid, 1 otherwise, printing one line per problem.
This enforces the pre-draft invariants and verdict/severity rules from SKILL.md
so the mistakes that quietly inflate a report are refused before a human reads it.
"""

import json
import re
import sys

FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
VERDICTS = ("confirmed", "needs_validation", "hardening", "rejected")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")

# verdict -> (required fields, forbidden fields). Common fields are checked separately.
RULES = {
    "confirmed": (
        ("severity", "evidence", "reproduction", "root_cause", "remediation"),
        ("blocker", "validation_plan", "reason", "note"),
    ),
    "needs_validation": (
        ("blocker", "validation_plan"),
        ("severity", "confidence", "reproduction", "remediation", "reason", "note"),
    ),
    "hardening": (
        ("note",),
        ("severity", "evidence", "reproduction", "blocker", "validation_plan", "reason"),
    ),
    "rejected": (
        ("reason",),
        ("severity", "reproduction", "remediation", "blocker", "validation_plan", "note"),
    ),
}


def nonempty_str(value):
    return isinstance(value, str) and value.strip() != ""


def nonempty_list(value):
    return isinstance(value, list) and len(value) > 0


def check_record(index, rec, seen_ids, errors):
    # A label for messages: prefer the id, fall back to the array index.
    rid = rec.get("id") if isinstance(rec, dict) else None
    label = rid if nonempty_str(rid) else f"#{index}"

    def err(msg):
        errors.append(f"[{label}] {msg}")

    if not isinstance(rec, dict):
        errors.append(f"[#{index}] record is not a JSON object")
        return

    # --- common fields ---
    if not nonempty_str(rid):
        err("missing or empty 'id'")
    elif not FINGERPRINT.match(rid):
        err(f"'id' does not match fingerprint pattern {FINGERPRINT.pattern}")
    else:
        if rid in seen_ids:
            err("duplicate 'id' (ids must be unique within the file)")
        seen_ids.add(rid)

    if not nonempty_str(rec.get("title")):
        err("missing or empty 'title'")
    if not nonempty_str(rec.get("location")):
        err("missing or empty 'location'")

    verdict = rec.get("verdict")
    if verdict not in VERDICTS:
        err(f"'verdict' must be one of {VERDICTS}, got {verdict!r}")
        return  # per-verdict checks are meaningless without a known verdict

    required, forbidden = RULES[verdict]

    for field in forbidden:
        if field in rec:
            err(f"{verdict} record must not carry '{field}'")

    for field in required:
        if field not in rec:
            err(f"{verdict} record is missing required '{field}'")

    # --- per-verdict semantics ---
    if verdict == "confirmed":
        sev = rec.get("severity")
        if "severity" in rec and sev not in SEVERITIES:
            err(f"'severity' must be one of {SEVERITIES}, got {sev!r}")
        conf = rec.get("confidence")
        if "confidence" in rec:
            if conf not in CONFIDENCES:
                err(f"'confidence' must be one of {CONFIDENCES}, got {conf!r}")
            elif conf == "low":
                err("confirmed + low confidence cannot coexist — downgrade to a candidate")
        if "evidence" in rec and not nonempty_list(rec["evidence"]):
            err("confirmed record needs a non-empty 'evidence' array")
        for field in ("reproduction", "root_cause", "remediation"):
            if field in rec and not nonempty_str(rec[field]):
                err(f"'{field}' must be a non-empty string")

    elif verdict == "needs_validation":
        if "blocker" in rec and not nonempty_str(rec["blocker"]):
            err("'blocker' must be a non-empty string (one concrete missing fact)")
        plan = rec.get("validation_plan")
        if "validation_plan" in rec:
            if not isinstance(plan, dict):
                err("'validation_plan' must be an object")
            elif not (nonempty_str(plan.get("local")) or nonempty_str(plan.get("owner_observed"))):
                err("'validation_plan' needs a non-empty 'local' or 'owner_observed' step")

    elif verdict == "hardening":
        if "note" in rec and not nonempty_str(rec["note"]):
            err("'note' must be a non-empty string")

    elif verdict == "rejected":
        if "reason" in rec and not nonempty_str(rec["reason"]):
            err("'reason' must be a non-empty string")


def main(argv):
    if len(argv) != 2:
        print("usage: validate_findings.py <findings.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"error: no such file: {argv[1]}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: {argv[1]} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, list):
        print("error: top-level value must be a JSON array of findings", file=sys.stderr)
        return 1

    errors = []
    seen_ids = set()
    for index, rec in enumerate(data):
        check_record(index, rec, seen_ids, errors)

    if errors:
        for line in errors:
            print(line)
        print(f"\n{len(errors)} problem(s) in {len(data)} record(s).", file=sys.stderr)
        return 1

    print(f"ok: {len(data)} record(s) valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
