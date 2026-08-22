# Project context for Claude Code

## What this is

A static analysis tool that derives MySEQ memory offsets from `eqgame.exe`
(64-bit PE) by signature scanning. Read `README.md` first — it explains the
approach. The core pipeline works and is tested; the work below is extension
and hardening.

## Non-negotiable invariants

Violating any of these produces a tool that fails silently, which is worse than
one that fails loudly.

1. **RIP-relative math is `target = insn_va + insn_len + disp32`.** The
   displacement is relative to the address of the *next* instruction. Never
   `insn_va + disp`.
2. **A signature must match exactly once.** Zero matches means it broke; two or
   more means it is ambiguous. Both are failures. Never take "the first match".
3. **Never wildcard non-RIP displacements.** The `0x564` in `mov eax, [rcx+0x564]`
   is a struct member offset — stable and highly selective. Only RIP-relative
   disp32s, branch targets, and immediates inside the image get wildcarded.
4. **Never emit an unvalidated address.** Everything goes through
   `validate.py` first.
5. **Disagreement is reported, never hidden.** If signatures vote differently,
   surface it.

## Testing

`python3 tests/test_pipeline.py` — must stay at 10/10 (grows as behavior is
added; do not shrink it). It builds a synthetic image, simulates a patch by
moving the global and shifting the code, and checks the signatures still
resolve correctly. Add a case here for every behaviour you add. Do not weaken
existing assertions to make new code pass.

The real oracle is `cli.py selftest` run across two real consecutive patches.
If binaries exist under `binaries/`, use them.

## Tasks, in priority order

### 1. Historical cross-patch harness
Add `cli.py crosscheck` that walks every consecutive pair of
(binary, known-offsets) under `binaries/` and `known/`, builds from the older
and resolves against the newer, and prints a survival-rate matrix: per offset,
per signature, how many patch boundaries it survived. Persist results to
`crosscheck_report.json`.

This is the highest-value addition. Everything else is guesswork without it.

### 2. Scoring calibration
`sigbuild.score_signature` currently uses hand-picked weights. Once
crosscheck data exists, refit them against measured survival. Do not tune
weights before there is data to tune against.

### 3. Struct offset derivation (`extract: "insn_disp"`) — DONE (2026-08-21)
`eqoffsets/structsig.py` now derives these. It anchors candidate sites
(base register provably reached via a known-safe dereference like
`NextOffset`/`PrevOffset`, or via a nearby reference to an already-resolved
global) before ever building a signature for one — unanchored sites never get
to vote. This was not a theoretical precaution: an early manual derivation of
`HideOffset` for the 08/19/2026 patch trusted an unanchored, byte-identical
match and got it wrong (it was a qword store in an unrelated, unmodified
function that happened to share the same struct offset); a published list
caught it, and `test_struct_offset_rejects_unanchored_decoy` in
`tests/test_pipeline.py` encodes that exact failure mode as a regression
test. `cli.py build` derives struct signatures automatically now (skip with
`--no-structs`); `cli.py resolve` overlays a field only when its anchored
signatures show no *dissent* (`Resolution.consistent`, distinct from
`unanimous` — a signature that fails to fire is not the same as one that
disagrees) and otherwise falls back to `--known` with a printed
`UNCONFIRMED` + vote breakdown; `cli.py selftest` checks struct fields
against ground truth the same way it checks globals.

Real-world result against the 07/17→08/19/2026 boundary: of 22 struct
fields, 4 genuine shifts were correctly auto-derived (`ClassOffset`,
`RaceOffset`, `OwnerIDOffset`, `PrimaryOffset`), several unchanged fields
were correctly confirmed, 3 fields with genuinely ambiguous (not just
thin) votes were correctly left `UNCONFIRMED` rather than guessed
(`HideOffset`, `LevelOffset`, `OffhandOffset` — passing values, but not
ones the tool should claim credit for), and disp8-encoded fields
(`NextOffset`, `X/Y/ZOffset`, etc.) remain out of scope by design — see
README "Known limits" for why. Zero wrong answers were auto-applied.

Remaining headroom, if revisited: more anchored signatures per field (raise
`--keep` for structs specifically) might resolve some of the currently-tied
fields with real evidence instead of leaving them unconfirmed. Do not lower
the bar (e.g. accepting a bare plurality without `consistent`) to shrink that
list — an honest `UNCONFIRMED` is the correct output when the evidence
is genuinely thin, not a bug to paper over.

### 4. Performance
`refs.find_refs` is numpy-vectorised and fine. If `sigbuild` becomes slow on a
large `.text`, cache compiled patterns and reuse section data rather than
re-slicing. Do not optimise before measuring.

### 5. Robustness
- `build` should fail loudly and non-zero if any offset yields zero signatures.
- `resolve` should print the section name each resolved address landed in.
- Add `--json` output to `resolve` for scripting.

## Style

Plain stdlib plus `pefile`, `capstone`, `numpy`. No new dependencies without
asking. Comments explain *why* a rule exists, not what the line does — the
existing comments in `refs.py` are the intended register.

## Out of scope

Do not add process attachment, memory reading, injection, or any runtime
component. This tool parses a file on disk and that is a deliberate design
boundary — it is what makes it work on Linux without Wine involvement.
