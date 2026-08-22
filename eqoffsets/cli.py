import argparse
import configparser
import datetime
import hashlib
import json
import os
import sys

from .pe import PEImage
from .sigbuild import build_offset_signatures
from .structsig import build_struct_offset_signatures
from .resolve import resolve_all
from .validate import validate_all, validate_struct_offset, print_report
from .emit_ini import write_ini
from .buildinfo import client_hash as extract_client_hash, extract_build_string

# Struct sections eligible for anchored insn_disp derivation (structsig.py).
# WorldInfo Offsets is deliberately excluded: those are bit positions in a
# packed bitfield, not ModRM struct-member displacements, so this whole
# approach does not apply to them.
STRUCT_SECTIONS = ("SpawnInfo Offsets", "GroundItem Offsets")
# These fields are used AS anchors (structsig's safe_disps) for deriving
# everything else in their section, so deriving them from themselves would
# be circular -- and they're small enough to be disp8-encoded anyway, which
# this scan doesn't cover. Carried forward verbatim.
ANCHOR_FIELDS = ("NextOffset", "PrevOffset")


def _struct_key(section, field):
    """SpawnInfo Offsets and GroundItem Offsets both have XOffset/YOffset/
    ZOffset/NameOffset/NextOffset/PrevOffset -- field name alone is not a
    safe dict key across sections, so every struct-offset entry is keyed by
    (section, field) and carries both back out for reporting/INI-writing.
    """
    return f"{section}::{field}"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def parse_addr(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def _struct_anchors(known):
    """(safe_disps, trusted_globals) available to anchor struct-offset derivation."""
    static = known.get("static_sections", {})
    safe_disps = set()
    for sec_name in STRUCT_SECTIONS:
        for field in ANCHOR_FIELDS:
            v = static.get(sec_name, {}).get(field)
            if v is not None:
                try:
                    safe_disps.add(parse_addr(v))
                except (ValueError, TypeError):
                    pass
    trusted_globals = set()
    for v in known.get("memory_offsets", {}).values():
        try:
            trusted_globals.add(parse_addr(v))
        except (ValueError, TypeError):
            pass
    return safe_disps, trusted_globals


def open_image(path):
    image = PEImage(path)
    if not image.is_x64:
        sys.exit(f"{path} is not a 64-bit PE (machine=0x{image.machine:X})")
    print(f"loaded {path}")
    print(f"  image base 0x{image.image_base:X}, "
          f"{len(image.exec_sections())} executable section(s)")
    return image


# ---------------------------------------------------------------- build

def cmd_build(args):
    known = load_json(args.known)
    image = open_image(args.binary)

    db = {
        "meta": {
            "source_binary": args.binary,
            "sha256": sha256(args.binary),
            "image_base": f"0x{image.image_base:X}",
            "built_utc": datetime.datetime.utcnow().isoformat(timespec="seconds"),
            "patch_date": known.get("patch_date"),
        },
        "offsets": {},
    }

    print("\nbuilding signatures...")
    for name, value in known["memory_offsets"].items():
        target = parse_addr(value)
        sigs = build_offset_signatures(image, name, target, keep=args.keep)
        db["offsets"][name] = {
            "known_value": f"0x{target:X}",
            "signatures": sigs,
        }

    total = sum(len(e["signatures"]) for e in db["offsets"].values())
    empty = [n for n, e in db["offsets"].items() if not e["signatures"]]

    db["struct_offsets"] = {}
    struct_empty = []
    if not args.no_structs:
        safe_disps, trusted_globals = _struct_anchors(known)
        static = known.get("static_sections", {})
        print("\nderiving struct member offsets (anchored, extract=insn_disp)...")
        for sec_name in STRUCT_SECTIONS:
            for field, value in static.get(sec_name, {}).items():
                if field in ANCHOR_FIELDS:
                    continue
                try:
                    old_disp = parse_addr(value)
                except (ValueError, TypeError):
                    continue
                if old_disp == 0:
                    continue  # disp32==0 matches every bare [reg]; not a usable anchor value
                sigs = build_struct_offset_signatures(
                    image, field, old_disp,
                    safe_disps=safe_disps, trusted_globals=trusted_globals,
                    keep=args.keep)
                db["struct_offsets"][_struct_key(sec_name, field)] = {
                    "section": sec_name,
                    "field": field,
                    "known_value": f"0x{old_disp:X}",
                    "signatures": sigs,
                }
                if not sigs:
                    struct_empty.append(f"{sec_name}.{field}")

    with open(args.out, "w") as fh:
        json.dump(db, fh, indent=2)

    struct_total = sum(len(e["signatures"]) for e in db["struct_offsets"].values())
    print(f"\nwrote {args.out}: {total} global signature(s) across "
          f"{len(db['offsets'])} offset(s), {struct_total} struct signature(s) across "
          f"{len(db['struct_offsets'])} field(s)")
    if empty:
        print(f"NO SIGNATURES for: {', '.join(empty)} -- these will fail at resolve time")
    if struct_empty:
        print(f"undetermined struct field(s): {', '.join(struct_empty)} -- "
              f"resolve will carry these forward from --known unverified")
    return 0 if not empty else 1


# -------------------------------------------------------------- resolve

def cmd_resolve(args):
    sigdb = load_json(args.sigs)
    known = load_json(args.known) if args.known else {}
    image = open_image(args.binary)

    resolutions = resolve_all(image, sigdb)
    report = validate_all(image, resolutions)
    clean = print_report(resolutions, report)

    failed = [n for n, r in resolutions.items() if not r.ok]
    split = [n for n, r in resolutions.items() if r.ok and not r.unanimous]

    if failed:
        print(f"\nUNRESOLVED: {', '.join(failed)}")
    if split:
        print(f"DISAGREEMENT (review before use): {', '.join(split)}")

    # Struct member offsets: start from --known verbatim (old behavior), then
    # overlay any field this binary's own signatures confirm unanimously.
    # A field that resolves but disagrees, or that has no signatures at all
    # (old sigs.json, or structsig couldn't anchor it), keeps the --known
    # value and is flagged as unverified rather than silently trusted.
    static = {sec: dict(fields) for sec, fields in known.get("static_sections", {}).items()}
    struct_sigs = sigdb.get("struct_offsets", {})
    struct_undetermined = []
    if struct_sigs:
        struct_resolutions = resolve_all(image, {"offsets": struct_sigs})
        print("\n--- struct member offsets (anchored derivation) ---")
        for key, entry in struct_sigs.items():
            sec_name = entry.get("section", "SpawnInfo Offsets")
            field = entry.get("field", key)
            r = struct_resolutions.get(key)
            problems = validate_struct_offset(field, r.value if (r and r.ok) else None)
            known_val = static.get(sec_name, {}).get(field)

            if r and r.ok and r.consistent and not problems:
                new_val = f"0x{r.value:x}"
                tag = ""
                if known_val is not None and known_val.lower() != new_val.lower():
                    tag = f"  (known-offsets had {known_val} -- updating)"
                agree_tag = "unanimous" if r.unanimous else f"{r.agreement}/{r.agreement} fired, no dissent"
                print(f"  {field}: 0x{r.value:X} [{agree_tag}]{tag}")
                static.setdefault(sec_name, {})[field] = new_val
            else:
                fallback = known_val if known_val is not None else "?"
                why = problems[0] if problems else (r.summary() if r else "no signatures")
                print(f"  {field}: UNCONFIRMED ({why}) -- keeping known-offsets value {fallback}")
                if r:
                    for sid, val in r.votes.items():
                        tag = "" if val == r.value else "  <- disagrees"
                        print(f"      - {sid}: voted 0x{val:X}{tag}")
                    for sid, reason in r.failures.items():
                        print(f"      - {sid}: {reason}")
                struct_undetermined.append(f"{sec_name}.{field}")
        if struct_undetermined:
            print(f"unconfirmed struct field(s), carried forward unverified: "
                  f"{', '.join(struct_undetermined)}")

    if args.out_ini:
        if failed and not args.force:
            print("\nrefusing to write an incomplete INI; pass --force to override")
            return 2
        memory = {n: r.value for n, r in resolutions.items() if r.ok}
        write_ini(args.out_ini, memory, static,
                  patch_date=args.patch_date,
                  build_string=extract_build_string(args.binary) or "generated by eqoffsets",
                  client_hash=extract_client_hash(args.binary))
        print(f"\nwrote {args.out_ini}")

    return 0 if (clean and not failed and not split) else 1


# ------------------------------------------------------------- selftest

def cmd_selftest(args):
    """Resolve a signature DB against a binary whose true offsets we know."""
    sigdb = load_json(args.sigs)
    known = load_json(args.known)
    image = open_image(args.binary)

    resolutions = resolve_all(image, sigdb)
    expected = {k: parse_addr(v) for k, v in known["memory_offsets"].items()}

    print("\n--- comparison against known-good offsets ---")
    passed = failed = 0
    for name, want in expected.items():
        r = resolutions.get(name)
        if r is None or not r.ok:
            print(f"  FAIL {name}: unresolved (expected 0x{want:X})")
            failed += 1
            continue
        if r.value == want:
            tag = "" if r.unanimous else f"  (split vote {r.agreement}/{r.total})"
            print(f"  ok   {name}: 0x{r.value:X}{tag}")
            passed += 1
        else:
            print(f"  FAIL {name}: got 0x{r.value:X}, expected 0x{want:X}")
            failed += 1

    struct_sigs = sigdb.get("struct_offsets", {})
    if struct_sigs:
        struct_resolutions = resolve_all(image, {"offsets": struct_sigs})
        known_static = known.get("static_sections", {})
        print("\n--- struct member offsets vs known-good ---")
        for key, entry in struct_sigs.items():
            sec_name = entry.get("section", "SpawnInfo Offsets")
            field = entry.get("field", key)
            want_str = known_static.get(sec_name, {}).get(field)
            if want_str is None:
                continue
            want = parse_addr(want_str)
            r = struct_resolutions.get(key)
            if r is None or not r.ok:
                print(f"  FAIL {field}: unresolved (expected 0x{want:X})")
                failed += 1
            elif r.value == want:
                tag = "" if r.unanimous else f"  (split vote {r.agreement}/{r.total})"
                print(f"  ok   {field}: 0x{r.value:X}{tag}")
                passed += 1
            else:
                print(f"  FAIL {field}: got 0x{r.value:X}, expected 0x{want:X}")
                failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------- crosscheck


def _check_pair(old_image, old_known_data, new_image, new_known_data, keep=5):
    """Build sigs from old_image, resolve against new_image, compare to new_known_data.

    Returns a dict keyed by offset name::

        {
          "expected": int,
          "got":      int | None,
          "passed":   bool,
          "unanimous": bool,
          "sig_results": {
              sig_id: {"matched": bool, "value": int|None,
                       "correct": bool, "failure": str|None}
          }
        }

    Exported (underscore-prefixed to mark it internal) so the test suite can
    call it directly with FakeImage instances.
    """
    sigs_by_offset = {}
    for name, value in old_known_data["memory_offsets"].items():
        target = parse_addr(value)
        sigs = build_offset_signatures(old_image, name, target, keep=keep, verbose=False)
        sigs_by_offset[name] = {"known_value": f"0x{target:X}", "signatures": sigs}

    sigdb = {"offsets": sigs_by_offset}
    resolutions = resolve_all(new_image, sigdb)
    expected = {k: parse_addr(v) for k, v in new_known_data["memory_offsets"].items()}

    result = {}
    for name, want in expected.items():
        r = resolutions.get(name)
        sig_results = {}
        for sig in sigs_by_offset.get(name, {}).get("signatures", []):
            sid = sig.get("id", "?")
            if r and sid in r.votes:
                sig_results[sid] = {
                    "matched": True,
                    "value": r.votes[sid],
                    "correct": r.votes[sid] == want,
                    "failure": None,
                }
            else:
                sig_results[sid] = {
                    "matched": False,
                    "value": None,
                    "correct": False,
                    "failure": (r.failures.get(sid) if r else None) or "unresolved",
                }
        result[name] = {
            "expected": want,
            "got": r.value if (r and r.ok) else None,
            "passed": r is not None and r.ok and r.value == want,
            "unanimous": r.unanimous if (r and r.ok) else False,
            "sig_results": sig_results,
        }
    return result


def cmd_crosscheck(args):
    """Walk consecutive (binary, known) pairs; print per-sig survival matrix."""
    binaries_dir = args.binaries_dir
    known_dir = args.known_dir

    # Discover dates that have both a binary and known offsets.
    binary_dates = {}
    if os.path.isdir(binaries_dir):
        for entry in sorted(os.listdir(binaries_dir)):
            exe = os.path.join(binaries_dir, entry, "eqgame.exe")
            if os.path.isfile(exe):
                binary_dates[entry] = exe

    known_dates = {}
    if os.path.isdir(known_dir):
        for fname in sorted(os.listdir(known_dir)):
            if fname.endswith(".json"):
                known_dates[fname[:-5]] = os.path.join(known_dir, fname)

    common = sorted(set(binary_dates) & set(known_dates))

    if len(common) < 2:
        print("crosscheck needs at least 2 patch dates with both a binary and known "
              f"offsets; found {len(common)}: {common or 'none'}")
        with open(args.out, "w") as fh:
            json.dump({
                "meta": {
                    "patches": common,
                    "boundaries_tested": 0,
                    "generated_utc": datetime.datetime.utcnow().isoformat(timespec="seconds"),
                },
                "boundaries": [],
                "survival": {},
            }, fh, indent=2)
        print(f"wrote {args.out} (nothing to test)")
        return 0

    boundaries = list(zip(common, common[1:]))
    print(f"patch dates: {', '.join(common)}")
    print(f"testing {len(boundaries)} consecutive boundary(ies)\n")

    # survival[offset_name][sig_id] = {"tested": N, "passed": N}
    survival = {}
    boundary_records = []
    any_failed = False

    for from_date, to_date in boundaries:
        print(f"--- {from_date} -> {to_date} ---")
        old_image = open_image(binary_dates[from_date])
        old_known = load_json(known_dates[from_date])
        new_image = open_image(binary_dates[to_date])
        new_known = load_json(known_dates[to_date])

        print("  building signatures from older binary...")
        pair = _check_pair(old_image, old_known, new_image, new_known, keep=args.keep)

        passed_n = failed_n = 0
        for name, entry in pair.items():
            want = entry["expected"]
            got = entry["got"]
            if entry["passed"]:
                tag = "" if entry["unanimous"] else "  [SPLIT]"
                print(f"    ok   {name}: 0x{got:X}{tag}")
                passed_n += 1
            else:
                got_str = f"0x{got:X}" if got is not None else "unresolved"
                print(f"    FAIL {name}: got {got_str}, expected 0x{want:X}")
                failed_n += 1
                any_failed = True
            for sid, sr in entry["sig_results"].items():
                if not sr["correct"]:
                    reason = sr["failure"] or (
                        f"voted 0x{sr['value']:X}" if sr["value"] is not None else "no match"
                    )
                    print(f"         - {sid}: {reason}")

        print(f"  {passed_n} passed, {failed_n} failed\n")

        # Accumulate survival counters.
        for name, entry in pair.items():
            survival.setdefault(name, {})
            for sid, sr in entry["sig_results"].items():
                rec = survival[name].setdefault(sid, {"tested": 0, "passed": 0})
                rec["tested"] += 1
                if sr["correct"]:
                    rec["passed"] += 1

        # Serialisable boundary record (ints -> hex strings).
        boundary_records.append({
            "from": from_date,
            "to": to_date,
            "offsets": {
                name: {
                    "expected": f"0x{entry['expected']:X}",
                    "got": f"0x{entry['got']:X}" if entry["got"] is not None else None,
                    "passed": entry["passed"],
                    "unanimous": entry["unanimous"],
                    "sig_results": {
                        sid: {
                            "matched": sr["matched"],
                            "value": f"0x{sr['value']:X}" if sr["value"] is not None else None,
                            "correct": sr["correct"],
                            "failure": sr["failure"],
                        }
                        for sid, sr in entry["sig_results"].items()
                    },
                }
                for name, entry in pair.items()
            },
        })

    # Print survival matrix.
    print("=== survival matrix ===")
    print(f"  {'offset':<22} {'sig':<22} {'tested':>6} {'passed':>6} {'rate':>6}")
    print("  " + "-" * 62)
    for offset_name in sorted(survival):
        for sig_id, stats in sorted(survival[offset_name].items()):
            t, p = stats["tested"], stats["passed"]
            rate = f"{100 * p // t}%" if t else "n/a"
            print(f"  {offset_name:<22} {sig_id:<22} {t:>6} {p:>6} {rate:>6}")

    report = {
        "meta": {
            "patches": common,
            "boundaries_tested": len(boundaries),
            "generated_utc": datetime.datetime.utcnow().isoformat(timespec="seconds"),
        },
        "boundaries": boundary_records,
        "survival": {
            name: {
                sid: {**s, "rate": s["passed"] / s["tested"] if s["tested"] else 0.0}
                for sid, s in sigs.items()
            }
            for name, sigs in survival.items()
        },
    }

    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nwrote {args.out}")

    return 1 if any_failed else 0


# -------------------------------------------------------------- update

def _latest_pair(known_dir, sigs_dir):
    """Newest date present in both --known-dir and --sigs-dir, or (None, None)."""
    def dates(d):
        return {f[:-5] for f in os.listdir(d) if f.endswith(".json")} if os.path.isdir(d) else set()
    common = sorted(dates(known_dir) & dates(sigs_dir))
    if not common:
        return None, None
    latest = common[-1]
    return os.path.join(sigs_dir, f"{latest}.json"), os.path.join(known_dir, f"{latest}.json")


def _prompt_existing_path(prompt, kind):
    """kind: 'file' or 'dir'. Reprompts on a bad path; 'q' aborts."""
    check = os.path.isfile if kind == "file" else os.path.isdir
    while True:
        raw = input(prompt).strip().strip('"')
        if raw.lower() in ("q", "quit", "exit"):
            return None
        path = os.path.expanduser(raw)
        if check(path):
            return path
        print(f"  can't find that {kind}, try again (or 'q' to quit): {path}")


def _norm_value(v):
    """Normalize a static-section value for comparison -- these are a mix of
    hex ('0x4b4', struct/memory offsets) and plain decimal ('10', used by
    [WorldInfo Offsets]); a blind int(v, 16) would silently misread "10" as
    16. Falls back to a case-folded string compare if it's neither.
    """
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except ValueError:
        return s.lower()


def _ini_up_to_date(ini_cp, memory, static):
    """True if every value eqoffsets can confirm already matches the ini."""
    if not ini_cp.has_section("Memory Offsets"):
        return False
    for name, value in memory.items():
        cur = ini_cp["Memory Offsets"].get(name)
        if cur is None or _norm_value(cur) != value:
            return False
    for sec, fields in static.items():
        if not ini_cp.has_section(sec):
            return False
        for k, v in fields.items():
            cur = ini_cp[sec].get(k)
            if cur is None or _norm_value(cur) != _norm_value(v):
                return False
    return True


def _resolve_struct_offsets(image, sigdb, static):
    """Overlay confidently-derived struct fields onto `static` in place (same
    accept/fallback policy as cmd_resolve: r.consistent, not mere r.ok) and
    return a list of (section, field, status) for reporting. Duplicated from
    cmd_resolve's inline version rather than shared, deliberately -- this
    command has different, terser reporting needs and the two are small
    enough that a shared abstraction wasn't worth the indirection.
    """
    notes = []
    struct_sigs = sigdb.get("struct_offsets", {})
    if not struct_sigs:
        return notes
    struct_resolutions = resolve_all(image, {"offsets": struct_sigs})
    for key, entry in struct_sigs.items():
        sec_name = entry.get("section", "SpawnInfo Offsets")
        field = entry.get("field", key)
        r = struct_resolutions.get(key)
        problems = validate_struct_offset(field, r.value if (r and r.ok) else None)
        if r and r.ok and r.consistent and not problems:
            static.setdefault(sec_name, {})[field] = f"0x{r.value:x}"
            notes.append((sec_name, field, "confirmed"))
        else:
            notes.append((sec_name, field, "unconfirmed"))
    return notes


def cmd_update(args):
    sigs_path, known_path = _latest_pair(args.known_dir, args.sigs_dir)
    if not sigs_path:
        print(f"no matching '{args.known_dir}/<date>.json' + '{args.sigs_dir}/<date>.json' "
              f"pair found -- nothing to update from")
        return 1

    sigdb = load_json(sigs_path)
    known = load_json(known_path)
    print(f"eqoffsets update -- using {os.path.basename(sigs_path)} "
          f"(patch {known.get('patch_date', '?')})\n")

    exe_path = args.exe or _prompt_existing_path("Path to your eqgame.exe: ", "file")
    if not exe_path:
        print("cancelled")
        return 1

    myseq_dir = args.myseq_dir or _prompt_existing_path(
        "Path to your MySEQ install folder (where myseqserver.ini lives): ", "dir")
    if not myseq_dir:
        print("cancelled")
        return 1

    ini_path = os.path.join(myseq_dir, "myseqserver.ini")
    image = open_image(exe_path)

    resolutions = resolve_all(image, sigdb)
    failed = [n for n, r in resolutions.items() if not r.ok]
    if failed:
        print(f"\nCould not determine {', '.join(failed)} from this binary. The bundled "
              f"signatures (from patch {known.get('patch_date', '?')}) may be too old for "
              f"this client -- a newer eqoffsets package is needed. Leaving "
              f"{'your existing myseqserver.ini' if os.path.isfile(ini_path) else 'nothing'} "
              f"untouched.")
        return 1
    memory = {n: r.value for n, r in resolutions.items() if r.ok}

    static = {sec: dict(fields) for sec, fields in known.get("static_sections", {}).items()}
    struct_notes = _resolve_struct_offsets(image, sigdb, static)

    existing = configparser.ConfigParser()
    have_existing = os.path.isfile(ini_path)
    if have_existing:
        existing.read(ini_path)

    if have_existing and _ini_up_to_date(existing, memory, static):
        print(f"\n{ini_path} already matches this eqgame.exe -- every offset eqoffsets "
              f"could confirm is already correct. Nothing to do.")
        return 0

    port = "5555"
    if have_existing and existing.has_section("Port") and existing.has_option("Port", "port"):
        port = existing["Port"]["port"]

    bhash = extract_client_hash(exe_path)
    bstring = extract_build_string(exe_path)
    if bstring is None:
        bstring = known.get("build_string") or "generated by eqoffsets"
        print(f"could not read a build string out of the binary -- using "
              f"'{bstring}' from the bundled known-offsets file instead\n")

    if known.get("binary_sha256", "").lower() == sha256(exe_path).lower():
        patch_date = known.get("patch_date") or datetime.date.today().strftime("%m/%d/%Y")
    else:
        patch_date = datetime.date.today().strftime("%m/%d/%Y")

    print(f"{'updating' if have_existing else 'creating'} {ini_path}:")
    print(f"  PatchDate   -> {patch_date}")
    print(f"  ClientHash  -> {bhash}")
    print(f"  BuildString -> {bstring}")
    port_note = "kept from existing config" if have_existing else "default, no existing config found"
    print(f"  port        -> {port}  ({port_note})")
    old_memory = existing["Memory Offsets"] if (have_existing and existing.has_section("Memory Offsets")) else {}
    for n, v in memory.items():
        tag = "" if n in old_memory and _norm_value(old_memory[n]) == v else "  <- changed"
        print(f"  {n} = 0x{v:X}{tag}")
    unconfirmed = [f"{sec}.{field}" for sec, field, status in struct_notes if status == "unconfirmed"]
    if unconfirmed:
        print(f"  struct field(s) carried forward unverified: {', '.join(unconfirmed)}")

    if not args.yes:
        answer = input("\nReplace myseqserver.ini now? [y/N]: ").strip().lower()
        if answer != "y":
            print("not written")
            return 0

    write_ini(ini_path, memory, static, patch_date=patch_date,
              build_string=bstring, client_hash=bhash, port=port)
    print(f"\nwrote {ini_path}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="eqoffsets",
        description="Derive MySEQ memory offsets from eqgame.exe by signature scanning.")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build signatures from a binary + known offsets")
    b.add_argument("--binary", required=True)
    b.add_argument("--known", required=True)
    b.add_argument("--out", default="sigs.json")
    b.add_argument("--keep", type=int, default=5)
    b.add_argument("--no-structs", action="store_true",
                    help="skip anchored struct-member offset derivation (globals only)")
    b.set_defaults(func=cmd_build)

    r = sub.add_parser("resolve", help="apply signatures to a new binary")
    r.add_argument("--binary", required=True)
    r.add_argument("--sigs", default="sigs.json")
    r.add_argument("--out-ini")
    r.add_argument("--known", help="known-offsets file: fallback/baseline for struct-member "
                                    "offsets that can't be independently confirmed this run")
    r.add_argument("--patch-date")
    r.add_argument("--force", action="store_true")
    r.set_defaults(func=cmd_resolve)

    s = sub.add_parser("selftest", help="resolve against a binary with known offsets and diff")
    s.add_argument("--binary", required=True)
    s.add_argument("--sigs", default="sigs.json")
    s.add_argument("--known", required=True)
    s.set_defaults(func=cmd_selftest)

    cc = sub.add_parser("crosscheck",
                        help="test signature survival across consecutive patch pairs")
    cc.add_argument("--binaries-dir", default="binaries")
    cc.add_argument("--known-dir", default="known")
    cc.add_argument("--out", default="crosscheck_report.json")
    cc.add_argument("--keep", type=int, default=5)
    cc.set_defaults(func=cmd_crosscheck)

    u = sub.add_parser("update",
                       help="interactively point at eqgame.exe + a MySEQ install and "
                            "write a corrected myseqserver.ini in place")
    u.add_argument("--exe", help="path to eqgame.exe (skips that prompt)")
    u.add_argument("--myseq-dir", help="MySEQ install folder (skips that prompt)")
    u.add_argument("--known-dir", default="known")
    u.add_argument("--sigs-dir", default="sigs")
    u.add_argument("--yes", action="store_true", help="skip the replace confirmation prompt")
    u.set_defaults(func=cmd_update)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
