# eqoffsets

Derives MySEQ `[Memory Offsets]` from `eqgame.exe` by signature scanning, so you
do not have to wait for someone else to publish them after a patch.

Static analysis only: it parses the PE file on disk. Nothing attaches to a
running process, so it works fine on Linux against a Wine prefix.

---

## Quick start

You don't need to understand how any of this works to use it. Three steps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m eqoffsets.cli update
```

`update` asks two questions the first time you run it -- the path to your
`eqgame.exe`, and the path to your MySEQ install folder (where
`myseqserver.ini` lives) -- then:

1. remembers both paths (in `~/.eqoffsets/config.json`), so it won't ask
   again next time. Pass `--exe`/`--myseq-dir` any time you need to point it
   somewhere else; doing so also updates what it remembers, so you only ever
   have to give a new path once. Delete the config file, or pass a fresh
   `--config <path>`, to reset;
2. resolves every offset it can against your binary;
3. either tells you your existing `myseqserver.ini` already matches (nothing
   written), or shows you exactly what would change and asks for a `y` before
   overwriting it in place. Your `[Port]` line is always preserved;
4. if a struct field couldn't be independently confirmed this run, it's
   carried forward from the last known-good value rather than guessed, and
   called out by name -- see "If a field says UNCONFIRMED" below.

`--yes` skips the confirmation prompt, for scripted use.

That's the whole workflow for almost everyone. Everything past this point is
either a quick reference for reading the output, or the deeper internals for
someone extending or auditing the tool -- skip straight to "Known limits" if
you just want to know what to watch out for.

---

## Reading the output

- **`unanimous`** — every signature agreed. Good, nothing to check.
- **`SPLIT`** — signatures disagreed, but a majority still won. Usually
  fine (see "Known limits"), worth a glance if you're being careful.
- **`FAILED`** / **`UNRESOLVED`** — no signature matched at all. `update`
  will refuse to touch your INI if this happens to a `[Memory Offsets]`
  entry; the bundled signature set is too old for this client and needs
  refreshing (see "Building your own signature set" below, or wait for an
  updated eqoffsets release).
- **`ERROR ... lands in executable section`** — a signature matched the
  wrong instruction. Do not use that result; something is wrong with the
  input, not just thin evidence.
- **`UNCONFIRMED`** (struct fields only, e.g. `[SpawnInfo Offsets]`) — the
  field's signatures either found nothing or actively disagreed, so the
  last known-good value was kept instead of guessing. See the next section.

---

## If a field says UNCONFIRMED

This is the case the whole project exists to handle without making you wait
on someone else. When it happens, look for `eqoffsets_review.md` --
`update` writes it next to your `myseqserver.ini`; `resolve` (see below)
writes it next to whatever `--out-ini` you gave it, or to
`./eqoffsets_review.md` otherwise; either way, the console output tells you
exactly where.

That file lists every candidate value the tool found, how many signatures
voted for each one, and the actual surrounding assembly for each candidate
-- the old binary's code where it was originally derived, next to the new
binary's code where it matched now, side by side. In most cases one
candidate is an obvious clean continuation of the same code and the others
are stale or coincidental; picking the right one is a ten-second read, not
a disassembly session. A short worked example:

```
### candidate `0x270` -- 4 vote(s): LevelOffset#2, ... [root]

old binary, as originally derived:
    -> mov byte ptr [rcx + 0x210], al

this binary:
    -> mov byte ptr [rcx + 0x270], al
```

Once you've picked the right value:

1. Edit your known-offsets file (`known/<date>.json`) and set that field.
2. Re-run `update` (or `resolve`, if you're doing this the manual way) --
   the carried-forward value was only ever a starting point.

Occasionally the code alone won't settle it -- multiple candidates look
like equally clean continuations of their own old site, because the patch
reorganized more than one region at once. That is a genuine ambiguity, not
a tool failure; the review doc says so plainly rather than picking one for
you, and at that point you either need to dig one level further (e.g. what
does a nearby `call` target actually do) or fall back to a published list
after all.

If you'd rather have the tool just pick a value automatically instead of
asking you, `resolve --best-effort` applies the plurality vote and labels
it `BEST-EFFORT` everywhere instead of falling back. Read `--help` before
using it: it states a real measured case where the plurality was wrong, not
a theoretical warning.

---

## Known limits

- **A struct field near the disp8/disp32 boundary** (roughly `0x80`) can
  flip encoding width across a patch, which changes the *length* of every
  instruction that touches it. Its signatures then stop matching entirely
  and it comes back unresolved rather than wrong -- expected, but it's the
  field most likely to need a manual look after a big struct reorg.
- **A field at offset 0** (e.g. `GroundItem.PrevOffset`) is often encoded
  with no displacement bytes at all, so there's nothing to read back except
  from sites where the compiler happened to emit an explicit zero.
- **`SPLIT` on a `[Memory Offsets]` value** has, in every real case measured
  so far, resolved correctly via majority vote once checked against a
  published list -- but it is still worth a glance, since "measured so far"
  is two patch boundaries, not a guarantee.
- **The PE loader is the least-tested seam.** The automated test suite
  drives the pipeline through a synthetic in-memory image; it doesn't
  exercise real `pefile` parsing. First run against a real binary, glance at
  the section list it prints.
- **Addresses are preferred-base VAs** (`image_base + rva`, i.e. `0x140...`),
  matching how published MySEQ lists are normally written. If a list ever
  gives RVAs instead, add `0x140000000` before putting them in a
  known-offsets file.
- **Scoring weights are calibrated on two patch boundaries.** Enough to
  confidently rank which anchoring strategies work (the gap between the
  worst and the best is large), not enough to fine-tune anything further.

---

## Legal

Daybreak's terms of service cover third-party tools that read game memory.
Enforcement lands on the account using them. Your call; just make it
knowingly.

---
---

# Internals and manual workflow

Everything below this line is for extending, auditing, or manually
rebuilding this tool's signature sets -- not needed to just run it.

Run the test suite after any change:

```bash
python3 tests/test_pipeline.py     # must print 26/26 passed
```

## The idea in one paragraph

Addresses move every patch. The *code that references* those addresses barely
changes, because the source did not change — only the compiler's layout did. So
we take the offsets someone already published for the current build, find every
instruction that references them, strip out the address bytes, and keep the
remaining opcode bytes as a fingerprint. Next patch, we search for those
fingerprints in the new binary and read the new addresses back out of whatever
we find.

### Why `+0x44E0` never worked

Adding a constant to every address assumes the whole data segment shifts
uniformly. It does not. Individual globals move by different amounts, some do
not move at all, and struct layouts change independently of everything else.

## Files

| file | role |
|---|---|
| `eqoffsets/pe.py` | PE loading, section bytes, VA math |
| `eqoffsets/scan.py` | wildcard byte-pattern matcher |
| `eqoffsets/refs.py` | finds instructions referencing a known global |
| `eqoffsets/sigbuild.py` | turns those into unique wildcarded signatures |
| `eqoffsets/codemap.py` | function boundaries from `.pdata`, correctly-aligned disassembly |
| `eqoffsets/anchor.py` | decides which `[reg+disp]` sites are really *this* struct |
| `eqoffsets/structsig.py` | turns anchored sites into signatures for struct member offsets |
| `eqoffsets/resolve.py` | matches signatures on a new binary, votes |
| `eqoffsets/validate.py` | sanity checks before anything is emitted |
| `eqoffsets/review.py` | builds `eqoffsets_review.md` for fields that need a manual look |
| `eqoffsets/config.py` | remembers `update`'s `--exe`/`--myseq-dir` between runs |
| `eqoffsets/emit_ini.py` | writes `myseqserver.ini` |
| `eqoffsets/buildinfo.py` | pulls `ClientHash` (sha1 of the file) and `BuildString` straight out of `eqgame.exe` |
| `eqoffsets/cli.py` | `build` / `resolve` / `selftest` / `crosscheck` / `update` |

## Building your own signature set from scratch

Only needed if you're not using the bundled signature sets under `sigs/` --
e.g. you're maintaining a fork, or the bundled sets have fallen too far
behind for `update` to resolve anything.

### 1. Set up a known-good pair

Copy `known_offsets.example.json` to `known/2025-10-15.json`, put the published
offsets in it, and save the **exact** `eqgame.exe` those offsets came from as
`binaries/2025-10-15/eqgame.exe`.

The offsets and the binary must match each other. If they do not, `build` will
report zero references found — which is the tool correctly telling you the
inputs are inconsistent, not a bug.

### 2. Build signatures

```bash
python3 -m eqoffsets.cli build \
  --binary binaries/2025-10-15/eqgame.exe \
  --known  known/2025-10-15.json \
  --out    sigs/2025-10-15.json
```

Expect a handful of reference sites per offset. One or two is workable but
fragile; zero means something is wrong with that address.

### 3. Prove it against itself

```bash
python3 -m eqoffsets.cli selftest \
  --binary binaries/2025-10-15/eqgame.exe \
  --sigs   sigs/2025-10-15.json \
  --known  known/2025-10-15.json
```

All 37 must pass -- six memory offsets and 31 struct fields. This only proves
the extraction math is right, not that the signatures survive a patch. That is
step 4, and it is the important one.

### 4. Prove it across a patch — do this before you need it

Take signatures built from an **older** binary and resolve them against a
**newer** binary whose offsets you also know:

```bash
python3 -m eqoffsets.cli selftest \
  --binary binaries/2025-11-19/eqgame.exe \
  --sigs   sigs/2025-10-15.json \
  --known  known/2025-11-19.json
```

This is the only measurement that tells you whether the tool works. Do it for
every pair of consecutive patches you can collect. A signature set that scores
37/37 across three or four historical patch boundaries is one you can rely on;
one you have never tested across a boundary is a guess with extra steps.

**Start collecting old `eqgame.exe` files and their published offset lists now.**
Every past patch you can pair up is a free test case, and they get harder to
find over time. This matters more than any other part of the project.

### 5. Patch day

```bash
python3 -m eqoffsets.cli resolve \
  --binary /path/to/wineprefix/.../eqgame.exe \
  --sigs   sigs/2025-10-15.json \
  --known  known/2025-10-15.json \
  --out-ini myseqserver.ini
```

`resolve` is `update`'s explicit, scriptable sibling: same accept/fallback
policy, but every path is given on the command line instead of asked or
remembered, and it exposes `--best-effort` and `--review-file` directly.

Then rebuild signatures from the new binary using the offsets you just derived,
so the database tracks the current build:

```bash
python3 -m eqoffsets.cli build --binary <new exe> --known <new offsets> --out sigs/<date>.json
```

---

## How the struct offsets are derived

`[SpawnInfo Offsets]`, `[GroundItem Offsets]` and `[WorldInfo Offsets]` are
ModRM displacements (`mov eax, [rcx+0x564]`), not globals. A bare search for
"every instruction touching `0x564`" turns up dozens of unrelated struct
fields that happen to share the number, and picking the wrong one is how this
project once published a `HideOffset` that was really a stack slot in an
unrelated function.

So the search never starts from the displacement. It starts from a global
that is already resolved and follows it forward through the code
(`eqoffsets/anchor.py`); a site counts only if its base register traces back
to one. Trust is established five ways, strongest first:

| anchor | meaning |
|---|---|
| `root` | the register came straight out of a resolved global (`mov rcx,[rip+CharInfo]`, or `lea` when the global *is* the struct) |
| `link` | walked to another instance through `NextOffset`/`PrevOffset` from an already-trusted register |
| `this` | a direct `call`, or a tail-call `jmp` straight to another function's entry point (MSVC's usual codegen for a one-line forwarder), made with a trusted register in `rcx` -- propagated to a fixpoint, this is what reaches the accessor methods where the interesting fields actually live |
| `linkseed` | a bare `mov rdx,[rax+PrevOffset]` with nothing behind it; weakest, and the only rule the old implementation had |
| `shape` | **off by default** -- a register used with several known field offsets. Measured at 82% cross-patch survival against 95-100% for the rest, and it fails specifically by insisting a moved field stayed put. `--struct-shape-anchor` opts in. |

Instruction alignment comes from the PE's own `.pdata` exception-unwind
table, which is an exact, compiler-authored map of ~26k function boundaries
covering 94% of `.text` -- not a guess based on `0xCC` padding.

`build` derives all of this automatically (`--no-structs` skips it).
`resolve` overlays a field only when its signatures agree with **no dissent**
(`Resolution.consistent` -- a signature that fails to fire across a patch is
not the same as one that actively disagrees, and only the latter is treated
as untrustworthy). Anything unconfirmed is carried forward from `--known`,
printed as `UNCONFIRMED` with the full vote breakdown and a review doc (see
"If a field says UNCONFIRMED" above), and never silently trusted. `selftest`
and `crosscheck` score these against ground truth exactly the way they score
the globals.

### Measured result

Two real patch boundaries so far, both built from the older binary and
scored against a published list for the newer one:

```
07/17/2026 -> 08/19/2026:  37 passed, 0 failed   (6 memory offsets + 31 struct fields)
08/19/2026 -> 09/11/2026:  36 passed, 1 failed
```

The 07/17→08/19 boundary includes the six fields that patch actually moved --
`LevelOffset` `0x564`→`0x210`, `HideOffset` `0x4d0`→`0x304`,
`OwnerIDOffset` `0x554`→`0x4b4`, `ClassOffset`, `RaceOffset`,
`PrimaryOffset`, `OffhandOffset` -- all derived rather than carried forward.
One field (`GroundItem.IdOffset`) drew a split vote and was correctly
reported `UNCONFIRMED` rather than claimed.

The 08/19→09/11 boundary again derived every real shift correctly (including
`OwnerIDOffset`, `ClassOffset`, `RaceOffset`, `PrimaryOffset`, `OffhandOffset`
all moving `+8` together) and again correctly declined to guess on the one
field it couldn't confirm: `SpawnInfo.LevelOffset` split 4-3-1 across three
candidate values but the plurality (`0x270`) happened to be right; the
"failure" reported by `selftest`/`crosscheck` is `SpawnInfo.HideOffset`,
where the plurality was **wrong** -- see "If a field says UNCONFIRMED" above
for the worked example, since it is the clearest real case yet for why
`resolve` requires no dissent at all rather than just a majority.

Run `crosscheck` to reproduce either boundary; it writes
`crosscheck_report.json` with per-signature and per-anchor-kind survival
rates. Aggregated across both boundaries so far:

```
  anchor              fired   right when fired
  root         169/204 (82%)      168/169 (99%)
  this         104/159 (65%)      101/104 (97%)
  linkseed      72/77  (93%)       68/72  (94%)
  rip_global    45/54  (83%)       45/45  (100%)
  link           8/8   (100%)         8/8   (100%)
```

Every wrong vote across both boundaries traced back to `linkseed`, the
weakest anchor tier by design -- exactly what it is scored last for.
