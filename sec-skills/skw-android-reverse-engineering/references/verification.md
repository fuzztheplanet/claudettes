# Verification: Claim-Strength Ladder & Definition of Done

This skill produces claims about someone else's software. Reverse-engineered
output is easy to overstate: a grep hit looks like a finding, a hook that
returns cleanly looks like a bypass, a decompiled string looks like a live
secret. This reference defines how strongly a claim may be stated, and when a
task is actually finished. It applies to **every** phase and every deliverable.

## Claim-strength ladder

Label every finding with exactly one strength. Never state a strength higher
than the evidence supports. When in doubt, downgrade.

| Strength | Meaning | What the proof looks like | How to write it |
|---|---|---|---|
| **OBSERVED** | You directly saw the behavior happen, in this session, and can reproduce it. | Command + its output, a saved logcat/Frida transcript, a response body, a screenshot. | "OBSERVED: launching `<activity>` with extra `X` instantiated `<fragment>` (logcat line at 12:03:11)." |
| **MEASURED** | Quantified with a repeatable procedure — a number, a diff, a byte count. | The measurement command and its result, run twice with the same outcome. | "MEASURED: patched 4 bytes at offset 0x1a2f; `dex_checksum_ok=true`; app cold-start unchanged at ~1.2s." |
| **INFERRED** | Deduced from indirect evidence. Consistent with what you saw, but not directly confirmed. | The indirect evidence + the reasoning step. | "INFERRED: `libflutter.so` + `libapp.so` present, so business logic is Dart AOT (not confirmed by decompiling the snapshot yet)." |
| **UNVERIFIED** | Hypothesis, or taken from documentation/prior knowledge, not tested against this target. | Cite the source; state what test would confirm it. | "UNVERIFIED: this packer is documented to dump via memory scan; not attempted on this build." |

### Rules

- **A grep/tool hit is a lead, not a finding.** It stays UNVERIFIED until you
  read the surrounding code (→ INFERRED) or observe the behavior (→ OBSERVED).
- **A bypass is only OBSERVED** when you saw the app run *past* the check **and**
  confirmed the check actually fired without your hook (e.g. the baseline crash
  in Step 7.2). A hook that "ran without error" on an app that never crashed is
  UNVERIFIED — you may have neutralized nothing.
- **"Vulnerable" requires OBSERVED or MEASURED proof of impact.** An exposed
  surface you did not exercise is INFERRED at best — report it as "exposed /
  untested", not "vulnerable".
- **A patch is not "applied" until proven landed** (a byte/class diff) **and**
  the app is verified to still run (install + launch health check). Until both,
  it is INFERRED.
- **Native and obfuscated code:** symbol-name matches are INFERRED, not OBSERVED
  — names can be misleading or stripped. Confirm by tracing or hooking.

### Tie-in to reporting (bug-bounty context)

Theoretical impact ("could allow…", "an attacker might…") is UNVERIFIED by
definition and **must not be written as a finding**. If you cannot label it
OBSERVED or MEASURED, it is not yet impact — it is a lead for more testing.
Carry the claim-strength label straight into the report's evidence section.

## Evidence you must keep

For anything above UNVERIFIED, retain and cite:

- The exact command(s) and the relevant machine-readable output lines.
- `file:line` references into the decompiled tree (e.g. `com/example/Api.java:42`).
- Saved Frida scripts (in the output dir) so a bypass is reproducible.
- Response excerpts / logcat / screenshots for runtime claims.
- For modifications: the before/after diff and the install+launch result.

## Definition of Done (completion criteria)

A phase — and the overall task — is **done** only when **all** of these hold.
"Scripts ran without error" is not done.

1. **Every hit confirmed.** Each grep/tool hit carried forward has been
   confirmed by reading the underlying code. Unconfirmed hits are dropped or
   explicitly labeled UNVERIFIED.
2. **Every endpoint traced.** Each reported API/endpoint has its call chain
   traced back to a user-facing entry point (Phase 4 format).
3. **Every bypass reproduced.** Each claimed protection bypass was reproduced
   from a clean start, and its script is saved in the output directory.
4. **Every finding labeled.** Each finding carries a claim-strength label and
   its supporting evidence.
5. **Every modification proven.** Any patch/repack is proven to have landed (diff)
   and the resulting app verified to install and launch.
6. **Output desensitized.** Deliverables contain no live secrets or tester/device
   identity that should not leave the box. (Redact keys, tokens, IMEIs, account
   handles in reports; keep raw values only in local evidence.)
7. **Negatives stated.** The deliverable says what was checked and found
   **safe/absent**, not only what was found present. A silent gap reads as
   "not checked".

## Anti-overclaim checklist (run before delivering)

- [ ] No claim is stated stronger than its evidence (re-check every "vulnerable",
      "bypassed", "confirmed").
- [ ] No theoretical/"could" impact is written as a finding.
- [ ] Every strong claim has a reproducible command or artifact attached.
- [ ] Symbol-name and grep-based claims are marked INFERRED unless traced/observed.
- [ ] What was checked-and-clean is listed alongside what was found.
