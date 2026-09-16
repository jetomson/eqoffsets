# eqoffsets

Derives MySEQ `[Memory Offsets]` from `eqgame.exe` by signature scanning, so you
do not have to wait for someone else to publish them after a patch.

Static analysis only: it parses the PE file on disk. Nothing attaches to a
running process, so it works fine on Linux against a Wine prefix.

---

## The idea in one paragraph

Addresses move every patch. The *code that references* those addresses barely
changes, because the source did not change — only the compiler's layout did. So
we take the offsets someone already published for the current build, find every
instruction that references them, strip out the address bytes, and keep the
remaining opcode bytes as a fingerprint. Next patch, we search for those
fingerprints in the new binary and read the new addresses back out of whatever
we find.

## Why `+0x44E0` never worked

Adding a constant to every address assumes the whole data segment shifts
uniformly. It does not. Individual globals move by different amounts, some do
not move at all, and struct layouts change independently of everything else.

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 tests/test_pipeline.py     # must print 21/21 passed
```

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
| `eqoffsets/emit_ini.py` | writes `myseqserver.ini` |
| `eqoffsets/buildinfo.py` | pulls `ClientHash` (sha1 of the file) and `BuildString` straight out of `eqgame.exe` |
| `eqoffsets/cli.py` | `build` / `resolve` / `selftest` / `crosscheck` / `update` |

---

## Runbook

### The easy way: `update`

If you just want to point at your own `eqgame.exe` and MySEQ install and be
done with it, skip everything below:

```bash
python3 -m eqoffsets.cli update
```

It asks two questions -- the path to `eqgame.exe`, and the path to the MySEQ
install folder -- picks the newest signature set bundled with the package,
resolves everything against your binary, and either tells you your existing
`myseqserver.ini` already matches (nothing written) or shows you exactly
what would change and asks for a yes before overwriting it in place. Your
existing `[Port]` value is always preserved. `PatchDate`/`ClientHash`/
`BuildString` are filled in from the binary itself. Struct fields it can't
independently confirm this run are carried forward from the bundled
known-offsets file rather than guessed, and are called out explicitly in the
output. `--exe`/`--myseq-dir`/`--yes` skip the prompts for scripted use.

This is what to hand a friend who has no interest in the rest of this
document.

### The manual way, if you want to build your own signature set from scratch

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

Then rebuild signatures from the new binary using the offsets you just derived,
so the database tracks the current build:

```bash
python3 -m eqoffsets.cli build --binary <new exe> --known <new offsets> --out sigs/<date>.json
```

---

## Reading the output

- `unanimous` — every signature agreed. Good.
- `SPLIT` — signatures disagreed. Majority wins but **check it by hand**;
  usually one signature matched something unrelated. (For memory offsets this
  can also just mean some signatures didn't fire while the rest agreed --
  `resolve`'s own struct-offset section calls that distinction out
  explicitly; for the `[Memory Offsets]` block, a SPLIT is still worth a
  manual look either way.)
- `FAILED` — no signature matched. Re-derive that offset manually and rebuild.
- `ERROR ... lands in executable section` — a signature matched the wrong
  instruction. Do not use the result.
- `UNCONFIRMED` (struct member offsets only) — the field's anchored
  signatures either found nothing or actively disagreed with each other, so
  `resolve` carried the `--known` value forward unverified rather than
  guessing. The printed vote breakdown shows exactly which signatures
  disagreed.

`resolve` refuses to write an INI if any memory offset is unresolved unless
you pass `--force`. Struct offsets never block the write -- an unconfirmed
one just falls back to the known-offsets value instead.

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
| `this` | a direct `call` made with a trusted register in `rcx`, propagated to a fixpoint -- this is what reaches the accessor methods where the interesting fields actually live |
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
printed as `UNCONFIRMED` with the full vote breakdown, and never silently
trusted. `selftest` and `crosscheck` score these against ground truth exactly
the way they score the globals.

### Measured result

Signatures built from the 07/17/2026 binary, resolved against 08/19/2026 and
compared to the published list for that build:

```
37 passed, 0 failed     (6 memory offsets + 31 struct fields)
```

That includes the six fields the 08/19 patch actually moved --
`LevelOffset` `0x564`→`0x210`, `HideOffset` `0x4d0`→`0x304`,
`OwnerIDOffset` `0x554`→`0x4b4`, `ClassOffset`, `RaceOffset`,
`PrimaryOffset`, `OffhandOffset` -- all derived rather than carried forward.
One field (`GroundItem.IdOffset`) drew a split vote and was correctly
reported `UNCONFIRMED` rather than claimed. Run `crosscheck` to reproduce it;
it writes `crosscheck_report.json` with per-signature and per-anchor-kind
survival rates.

## Known limits

- **A field that crosses the disp8/disp32 boundary** (under `0x80` to over,
  or back) changes the *length* of every instruction that touches it, so its
  signatures stop matching entirely and it is reported unresolved. That is the
  intended outcome -- the fingerprint has genuinely lost the field -- but it
  means a field sitting near `0x80` is the most likely one to need a manual
  re-derivation after a big struct reorg.
- **A field at offset 0** (`GroundItem.PrevOffset`) is encoded with no
  displacement bytes at all in the common case, so there is nothing to read
  back. It resolves only from sites where the compiler happened to emit an
  explicit `disp8` of zero.
- **Calibration rests on one patch boundary**, the only pair this repo has
  both binaries for. It is enough to rank the anchor kinds -- the gap between
  52% and 100% is not noise -- but not to fine-tune scoring weights. Collect
  more pairs; `crosscheck` is built to consume them.

`build` prints exactly which fields it could and couldn't anchor; `resolve`'s
`UNCONFIRMED` lines tell you which it carried forward without independent
confirmation. Read those before trusting an INI blindly, the same as you
would for `SPLIT` on the memory offsets.

**The PE loader is the least-tested seam.** The test suite drives the whole
pipeline through a synthetic in-memory image, which exercises the scanning,
wildcarding, RIP math and voting, but not `pefile` integration. First run
against a real binary, eyeball the section list it prints.

**Addresses are preferred-base VAs** (`image_base + rva`, so `0x140...`). That
matches how published MySEQ lists are written. If a list ever gives you RVAs
instead, add `0x140000000` before putting them in the known-offsets file.

---

## Legal

Daybreak's terms of service cover third-party tools that read game memory.
Enforcement lands on the account using them. Your call; just make it knowingly.
