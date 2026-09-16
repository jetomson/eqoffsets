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

`python3 tests/test_pipeline.py` — must stay at 21/21 (grows as behavior is
added; do not shrink it). It builds a synthetic image, simulates a patch by
moving the global and shifting the code, and checks the signatures still
resolve correctly. Add a case here for every behaviour you add. Do not weaken
existing assertions to make new code pass.

The real oracle is `cli.py selftest` run across two real consecutive patches.
If binaries exist under `binaries/`, use them.

## Tasks, in priority order

### 1. Historical cross-patch harness — DONE
`cli.py crosscheck` walks every consecutive pair of (binary, known-offsets)
under `binaries/` and `known/`, builds from the older and resolves against
the newer, and prints a survival-rate matrix: per offset, per signature, and
(since struct derivation landed) per *anchor kind*, split into "fired" and
"right when fired" — attrition and disagreement are different failures and
only the second condemns a rule. Results persist to
`crosscheck_report.json`.

Still the highest-value thing to feed: it has exactly **one** boundary
(07/17 → 08/19/2026) to learn from. Every extra binary+list pair collected
makes every calibration decision below less of a guess.

### 2. Scoring calibration
`sigbuild.score_signature` still uses hand-picked weights, deliberately.
What the one available boundary did support is `structsig.score_signature`'s
anchor-strength term, where the spread is large enough to be real (52% for
`shape` vs 95-100% for the dataflow anchors). What it did *not* support is
the length/wildcard weights: raising the length penalty to 0.5 and 1.0 and
re-measuring only moved which single GroundItem field split. That is noise,
and both scorers keep the original weights because of it. Do not refit until
crosscheck has more than one boundary.

### 3. Struct offset derivation (`extract: "insn_disp"`) — DONE, then rebuilt (2026-09-16)

**Current state.** All 31 struct fields across `[SpawnInfo Offsets]`,
`[GroundItem Offsets]` and `[WorldInfo Offsets]` are derived. Against the
07/17 → 08/19/2026 boundary: **37/37 correct** (6 globals + 31 fields), and
the emitted INI matches the published MySEQ list for that build on all 38
values. One field (`GroundItem.IdOffset`) drew a split vote and was reported
`UNCONFIRMED` rather than claimed — the `consistent` bar was *not* lowered to
absorb it.

Three things changed to get there, and the reasoning matters more than the
code:

1. **`codemap.py` — alignment from `.pdata`.** The PE ships its own
   exception-unwind table: ~26k exact function boundaries covering 94% of
   `.text`. Following a register requires decoding at the right alignment,
   and the old `0xCC`-padding heuristic silently gave up whenever it guessed
   wrong. `.pdata` is not a heuristic.

2. **`anchor.py` — anchoring inverted.** The old code searched for the
   displacement value and then asked whether the site looked anchored, which
   confined it to disp32 (a byte search cannot see a one-byte displacement)
   and to a backward peek of a few instructions. It now sweeps forward from
   resolved globals, propagating trust through linked-list walks, register
   copies and — critically — `this` into direct calls, to a fixpoint. That
   last one is what reaches accessor methods, which is where
   `OwnerIDOffset`, `HideOffset` and all of `[WorldInfo Offsets]` actually
   live. Encoding width stopped mattering, so disp8 fields came into scope.

3. **Two filters that are category errors, not tuning.** `rsp`/`rbp` bases
   are stack frames, never struct pointers — and the original published
   `HideOffset` mistake was trusting `mov [rbp+0x4d0], rsi`. `call`/`jmp`
   memory operands index a vtable, not a data member — and the single
   GroundItem.YOffset signature that voted wrong was built on
   `call qword ptr [rax+0x90]`.

**`shape` anchoring is off by default and should stay that way.** Trusting a
register because its function uses it with several known field offsets is
seductive and measured badly: 52% survival at 2 fields, 82% at 4, against
95-100% for every dataflow anchor. Worse, its errors are *not* random — they
cluster in initialiser functions that write many fields at once and did not
change across the patch, so a shape-anchored signature fails specifically by
insisting a field that moved stayed put. That is the HideOffset failure mode
reproduced exactly. Turning it off cost zero coverage. `--struct-shape-anchor`
opts in for the day a field loses its dataflow anchors entirely.

**`[WorldInfo Offsets]` was never a bitfield.** The old README asserted these
were bit positions in a packed bitfield and therefore out of reach. They are
plain byte displacements into the world-info block (`movzx ecx, byte ptr
[rcx+0xa]`), and all five derive normally once anchoring can follow
`WorldAddr` through a call. They are written in **decimal** in published
lists, which is a real trap: `parse_addr` read `"10"` as `0x10` and reported
three correct derivations as failures. Struct values now carry a per-section
`radix` end to end.

**Do not** lower `Resolution.consistent` to a plurality to shrink the
`UNCONFIRMED` list. It is currently one field long and honest.

---

#### Historical record (2026-08-21) — the first implementation

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

That headroom note ("raise `--keep` for structs specifically") turned out to
be correct and is now `--struct-keep`, defaulting to 9 against `--keep`'s 5.
It was not sufficient on its own — see the rebuild above for what actually
closed the gap.

### 4. Performance
`refs.find_refs` is numpy-vectorised and fine. If `sigbuild` becomes slow on a
large `.text`, cache compiled patterns and reuse section data rather than
re-slicing. Do not optimise before measuring.

Measured for the anchoring sweep, since it is the one genuinely expensive
addition: a full `build` against the real 15 MB `eqgame.exe` is ~32s, of
which the sweep is ~25s (2.2M instructions decoded across 26.6k functions,
then a shrinking worklist for `this` propagation — round 0 touches every
function, round 1 about 760, and it converges by round 5). `CodeMap`
deliberately does **not** cache decoded instructions: holding all 2.2M
capstone objects costs gigabytes to save a few seconds of re-decoding. That
was measured too, not assumed.

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
