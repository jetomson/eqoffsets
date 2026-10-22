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

`python3 tests/test_pipeline.py` — must stay at 33/33 (grows as behavior is
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

Still the highest-value thing to feed. It now has **three** boundaries
(07/17 → 08/19 → 09/11 → 10/19/2026). Every extra binary+list pair
collected makes every calibration decision below less of a guess.

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

### 3b. A second real boundary, and the honest answer to "what about UNCONFIRMED fields" (2026-09-16)

Pulled the live 09/11/2026 client from disk, resolved it cold against the
08/19 signature set (no known-offsets file for it yet), then scored it
against a published list once the user provided one: **36/37**, every real
shift correctly derived (`OwnerIDOffset`, `ClassOffset`, `RaceOffset`,
`PrimaryOffset`, `OffhandOffset` all `+8` together), one field
(`SpawnInfo.HideOffset`) correctly left `UNCONFIRMED`. See
`known/2026-09-11.json`'s `_provenance` for the full vote breakdown.

That raised the real question this project exists to answer: if `resolve`
won't guess, and the whole point is not waiting on someone else's list, what
*do* you do with an `UNCONFIRMED` field? Investigating the actual failure
(not guessing at a fix) turned up two separate, honest things, not one:

1. **A real, safe widening: tail-call `this` propagation.** The old rule only
   propagated trust through a direct `call`; it now also recognizes an
   unconditional `jmp` straight to another function's entry point (a
   tail call) as passing `this` the same way, since `codemap.function_starts`
   (from `.pdata`) makes it possible to tell a tail call apart from ordinary
   in-function control flow. This gained `LevelOffset` a genuine extra
   anchored site and cost nothing in the aggregate survival numbers — but,
   reported plainly rather than oversold, it did **not** flip either
   `HideOffset` or `LevelOffset` to confirmed at the 08/19→09/11 boundary.
   `HideOffset`'s real accessor still wasn't reached by any direct-call or
   tail-call path in that binary; there was nothing more to widen into.

2. **The actual answer: `resolve` now shows you the competing code.** For
   every `UNCONFIRMED` field, `resolve` disassembles a window at each
   distinct candidate value's site — the new binary always, and the *old*
   binary too when it's still on disk (via `sigdb["meta"]["source_binary"]` +
   a sha256 check), side by side. This is the exact manual technique
   `known/2026-08-19.json`'s provenance describes doing by hand
   ("eyeballing that the surrounding disassembly is the literal same code
   shape"), just automated far enough that most cases don't need a
   disassembler opened separately. Turns "wait days for a published list"
   into "read a few lines of asm now." `LevelOffset`'s three candidates make
   this trivial — one is an obviously stale value, one is a clean
   byte-identical continuation. `HideOffset` is the honest counterexample:
   both `0x314` and the true `0x504` show equally clean byte-identical
   continuations of their own old sites, because this patch reorganized both
   regions. The tool cannot manufacture certainty that isn't there; showing
   the real code is the ceiling of what static analysis can hand you without
   game-semantic knowledge of what each accessor is for.

3. **`--best-effort`, opt-in, for when a number now beats none.** Applies the
   raw plurality instead of falling back to `--known`, labeled `BEST-EFFORT`
   in the console output (never silently merged with confirmed fields — MySEQ's
   ini format has no comment syntax to flag it inside the file itself, which
   is why this is off by default rather than a quieter warning). Its own
   `--help` text states the real, measured risk rather than hedging: on
   `HideOffset` above, best-effort's plurality (`0x314`) would have been
   **wrong** — 2 stale votes outvoting the 1 correct one. `LevelOffset`'s
   plurality happened to be right. Do not present this flag as safe; it isn't,
   and the honest framing is what makes it trustworthy to reach for when the
   risk is acceptable.

Aggregate anchor-kind survival at the time spanned two boundaries: root 99%,
this 97%, link/rip_global 100%, linkseed 94%, and every wrong vote traced to
`linkseed`. **The third boundary broke that claim**: see 3d.

### 3c. A standing artifact for UNCONFIRMED fields, and remembered `update` paths (2026-09-16)

Two follow-ups to 3b, both requested directly rather than guessed at:

1. **`eqoffsets/review.py` — the candidate comparison as a file, not just
   console scrollback.** `resolve`/`update` write `eqoffsets_review.md`
   whenever a struct field ends UNCONFIRMED or BEST-EFFORT: a summary
   table, then per field every candidate's old/new disassembly windows,
   then a short "how to resolve this by hand" walkthrough. Built from the
   exact same report dicts (`build_field_report`) the console printer
   consumes (`cli._print_candidates`), specifically so the two can never
   drift into saying different things about the same field — a real risk
   the first version of this (inline printing duplicated between
   `cmd_resolve` and `cmd_update`) would have created. `_evaluate_struct_fields`
   is the other half of that convergence: one shared accept/fallback
   decision function replacing what used to be two separately-maintained
   copies (`cmd_resolve`'s inline version and `_resolve_struct_offsets`).

2. **`eqoffsets/config.py` — `update` remembers `--exe`/`--myseq-dir`.**
   Plain JSON at `~/.eqoffsets/config.json` (temp-file-then-rename to avoid
   a truncated write on crash). An explicit CLI value always overrides for
   that run *and* becomes the new remembered value, so redirecting the tool
   at a new install is a one-time thing, never a recurring flag. A
   remembered path that no longer resolves (`os.path.isfile`/`isdir`) is
   never trusted silently — `_remembered_path` re-prompts instead, since a
   stale path pointing at last patch's binary would be exactly the kind of
   silent-wrong-input CLAUDE.md's invariants exist to prevent elsewhere.

Also folded into this pass: the README was restructured so "how to use
this" (Quick start, Reading the output, If a field says UNCONFIRMED, Known
limits) comes first and needs no background, with all the anchoring
rationale, the manual from-scratch signature-building runbook, and the
measured survival numbers demoted below a clear `---` divider as
"Internals and manual workflow." Do not let that divider erode over
time — the whole point was that a first-time reader never has to scroll
past derivation theory to find out what a `SPLIT` result means.

### 3d. Third boundary (10/19/2026), and the access-width check (2026-10-21)

Resolved the 10/19/2026 client cold against the 09/11 signatures, then
scored it against the published 10/21 list (showeq.net thread 8425):
**39/40**. The two big shifts (`OwnerIDOffset` `0x54c`→`0x334`, `HideOffset`
`0x504`→`0x238`) confirmed on their own. The one miss was `LevelOffset`. Its
plurality, `0x52c` (4 votes), was right, but a single dissenting vote
(`0x268`, from `lea rcx, [rdi+0x270]`) blocked it, so the stale `0x270` was
carried forward. Full breakdown in `known/2026-10-19.json`'s `_provenance`.

**Every wrong vote at this boundary was `this`-anchored**, not `linkseed`.
Aggregate across all three: root 99%, linkseed 96%, **this 95%**,
link/rip_global 100%. `this` propagation reaches methods of other structs
that share an offset; that is now the main source of dissent.

**The access-width check (`resolve.apply_width_rule`).** A struct member has
one declared type, so its real accesses agree on width (1/2/4/8 bytes, or
`addr` for `lea`; float and int of the same size count as the same, because
position floats are copied with `mov dword` as often as `movss`). `build`
records `width` on every struct signature and `width_mix` over the field's
*whole* anchored pool. A dissenting vote is discounted (still printed,
labeled, kept in `votes` and in `crosscheck_report.json`, never hidden) only
when:

- its width differs from the pool's dominant one;
- the on-width votes are unanimous;
- that dominant width covers ≥ `WIDTH_DOMINANCE` = 2/3 of the pool.

Below 2/3 it only adds an advisory line (console + review doc). Old sigs
files without widths leave it inert.

Two measured facts drive the design, and both matter more than the code:

1. **The reference width must come from the pool, not the kept signatures.**
   On 08/19 `HideOffset` the kept signatures were two 2-byte reads (wrong)
   and one 4-byte read (right). A majority taken among them picks the wrong
   width and throws away the only correct vote. The pool (10 × 4-byte,
   8 × 2-byte) gets it right. Across all three boundaries the pool's dominant
   width never disagreed with the correct votes.
2. **The 2/3 threshold is deliberately not tuned.** Simulated over all 93
   field results: every threshold from 50% to 67% gives zero wrong
   confirmations. 55% would rescue 4 fields, 60% 3, 67% 2. But the fields
   deciding between those (`HideOffset` pool at 56%, `LevelOffset` at 60%)
   are single data points. Picking the cutoff that rescues them is fitting
   to the cases being measured. At 2/3 the rule confirms only `NameOffset`
   (91%) and `GroundItem.IdOffset` (76%) on 09/11→10/19, and changes nothing
   on the older boundaries. Revisit only with more boundaries, same as task 2.

**Open problem: `GroundItem.YOffset`'s evidence is bad.** A Y coordinate is a
4-byte float, but its anchored pool at `0x90` is mostly 1-byte and 8-byte
accesses (only 2 of 26 sites are 4-byte, and neither became a signature).
Several kept signatures load a qword pointer from `+0x90`, null-check it and
call through it. The value has been "right" because Y never moved, not
because these sites are Y. Relatedly, `GroundItem` anchoring reaches far too
much code (~3,500 anchored sites at `PrevOffset` = `0x0`). That is likely
`this` propagation from `ItemsAddr` escaping into unrelated classes, and it
deserves its own investigation before GroundItem results are trusted on a
patch that actually moves them.

### 3e. Hand-picking UNCONFIRMED values inside `update` (2026-10-21)

Requested directly: when fields are UNCONFIRMED, `update` asks once whether
to choose them by hand. On yes, `cli._choose_field_value` lists each
candidate numbered, with how many of the field's signatures matched at that
value in the new binary, and the old/new code. These rules hold:

- It renders the same `build_field_report` dict as the review doc, so the
  console choice and the doc cannot disagree.
- The current value is always the last option and the default (Enter), so
  no, EOF and Enter all leave behavior exactly as before.
- A picked value still goes through `validate_struct_offset` (invariant 4).
  A sign-extended disp8 candidate can be negative.
- A picked field is status `selected`, labeled "selected by you" in the
  pre-write summary. It is never merged into "confirmed". The tool did not
  confirm it, and the summary is the last place a person can see that.
- `--yes` skips it, since `--yes` means non-interactive.

On the 10/19 patch-day run, picking `[1]` for `LevelOffset` made the written
INI match the published list on all 40 values.

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
