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
python3 tests/test_pipeline.py     # must print 6/6 passed
```

## Files

| file | role |
|---|---|
| `eqoffsets/pe.py` | PE loading, section bytes, VA math |
| `eqoffsets/scan.py` | wildcard byte-pattern matcher |
| `eqoffsets/refs.py` | finds instructions referencing a known global |
| `eqoffsets/sigbuild.py` | turns those into unique wildcarded signatures |
| `eqoffsets/structsig.py` | same idea, but for struct member offsets (`[SpawnInfo Offsets]` etc.) -- anchored, see "Known limits" |
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

All six must pass. This only proves the extraction math is right — not that the
signatures survive a patch. That is step 4, and it is the important one.

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
6/6 across three or four historical patch boundaries is one you can rely on;
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

## Known limits

**Struct offsets are derived where they can be anchored; carried forward
verbatim otherwise.** `[SpawnInfo Offsets]` and `[GroundItem Offsets]` are
ModRM displacements (`mov eax, [rcx+0x564]`), not globals, and a bare search
for "every instruction touching disp32==0x564" turns up dozens of unrelated
struct fields elsewhere in the binary that just happen to share the same
numeric offset. `eqoffsets/structsig.py` handles this by only trusting a
candidate site if it is *anchored* -- its base register is provably derived
from a known-safe dereference (`NextOffset`/`PrevOffset`, the linked-list
pointers) or sits near a reference to an already-resolved global. Unanchored
sites never get a signature built for them at all. `build` derives these
automatically; `resolve` overlays a field's known-offsets value only when its
anchored signatures agree with no dissent (`Resolution.consistent` in
`resolve.py` -- a signature that simply fails to fire across a patch is not
the same thing as one that actively disagrees, and only the latter is treated
as untrustworthy); anything unconfirmed is carried forward from `--known` and
printed clearly as such, never silently trusted. `selftest` checks these
against ground truth the same way it checks the globals.

Two things this does **not** cover, so treat them as still-manual:

- **disp8-encoded offsets** (roughly anything under `0x80` -- `NextOffset`,
  `PrevOffset`, `LastnameOffset`, `X/Y/ZOffset`, `GroundItem`'s
  `Id/DropIdOffset`) are packed into a single byte by the compiler and are not
  searched -- a byte-wide value search is both slow and far too noisy to
  anchor reliably across an 8&nbsp;MB `.text` section.
- **`[WorldInfo Offsets]`** are bit positions in a packed bitfield, not struct
  byte displacements, so this technique does not apply to them at all.

`build`'s output tells you exactly which fields it could and couldn't derive
for a given binary; `resolve`'s `UNCONFIRMED` lines tell you which fields it
carried forward without independent confirmation. Read those before trusting
an INI blindly, the same as you would for `SPLIT` on the memory offsets.

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
