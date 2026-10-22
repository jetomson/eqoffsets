import argparse
import configparser
import datetime
import hashlib
import json
import os
import sys

from .pe import PEImage
from .codemap import CodeMap
from .anchor import StructKind, find_anchored_sites
from .sigbuild import build_offset_signatures
from .structsig import signatures_from_sites, width_mix
from .resolve import resolve_all, resolve_struct_all, width_note, width_label
from .validate import validate_all, validate_struct_offset, print_report
from .emit_ini import write_ini
from .buildinfo import client_hash as extract_client_hash, extract_build_string
from .review import build_field_report, write_markdown
from . import config as pathconfig

# How each INI section's struct is reached from an already-resolved global,
# and how its values are written.
#
#   roots  -- memory_offsets entries that point at (or are) an instance. All
#             of them are tried; ones that turn out not to reach the struct
#             in a given build simply contribute no sites.
#   links  -- fields holding a pointer to another instance of the same
#             struct, so anchoring can walk the list. Empty for WorldInfo,
#             which is a single block rather than a list.
#   radix  -- how published MySEQ lists write this section. [WorldInfo
#             Offsets] is plain decimal; everything else is 0x-hex. Getting
#             this wrong silently reads "10" as 16.
STRUCT_SECTIONS = {
    "SpawnInfo Offsets": {
        "roots": ("SpawnHeaderAddr", "CharInfo", "TargetAddr"),
        "links": ("NextOffset", "PrevOffset"),
        "radix": 16,
    },
    "GroundItem Offsets": {
        "roots": ("ItemsAddr",),
        "links": ("NextOffset", "PrevOffset"),
        "radix": 16,
    },
    # Historically excluded on the theory that these were bit positions in a
    # packed bitfield. They are not -- they are plain byte displacements into
    # the world-info block, and once anchoring could follow WorldAddr through
    # a call into its accessors, all five turned out to be derivable like
    # anything else.
    "WorldInfo Offsets": {
        "roots": ("WorldAddr",),
        "links": (),
        "radix": 10,
    },
}


def _parse_disp(value, radix):
    """Read a struct-offset value written in this section's radix."""
    if not isinstance(value, str):
        return int(value)
    text = value.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, radix)


def _format_disp(value, radix):
    """Write a derived value back the way the section is normally written."""
    return f"0x{value:x}" if radix == 16 else str(value)


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


def _struct_plan(known):
    """Build the anchoring plan for this known-offsets file.

    Returns (kinds, want, fields) where `kinds` are StructKind specs for
    anchor.py, `want` restricts recorded displacements to the ones we are
    actually after, and `fields` is the flat [(section, field, old_disp)]
    worklist.
    """
    static = known.get("static_sections", {})
    globals_by_name = {}
    for name, value in known.get("memory_offsets", {}).items():
        try:
            globals_by_name[name] = parse_addr(value)
        except (ValueError, TypeError):
            continue

    kinds, want, fields = [], {}, []
    for sec_name, spec in STRUCT_SECTIONS.items():
        radix = spec["radix"]
        disps = {}
        for field, value in static.get(sec_name, {}).items():
            try:
                disps[field] = _parse_disp(value, radix)
            except (ValueError, TypeError):
                continue
        if not disps:
            continue
        kinds.append(StructKind(
            name=sec_name,
            root_globals={globals_by_name[g] for g in spec["roots"] if g in globals_by_name},
            link_disps={disps[f] for f in spec["links"] if f in disps},
            field_disps=set(disps.values()),
        ))
        want[sec_name] = set(disps.values())
        for field, disp in disps.items():
            fields.append((sec_name, field, disp))
    return kinds, want, fields


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
        kinds, want, fields = _struct_plan(known)
        print("\nderiving struct member offsets (anchored, extract=insn_disp)...")
        codemap = CodeMap(image)
        if not codemap.from_pdata:
            print("  WARNING: no usable .pdata function table; anchoring will be "
                  "much weaker on this image")
        print(f"  tracing {len(kinds)} struct(s) through {len(codemap.functions)} function(s)")
        anchored = find_anchored_sites(image, kinds, want=want, codemap=codemap,
                                       verbose=True, enable_shape=args.struct_shape_anchor)
        for sec_name, field, old_disp in fields:
            sites = anchored.get(sec_name, {}).get(old_disp, [])
            sigs = signatures_from_sites(image, field, sites, codemap=codemap,
                                         keep=args.struct_keep)
            db["struct_offsets"][_struct_key(sec_name, field)] = {
                "section": sec_name,
                "field": field,
                "radix": STRUCT_SECTIONS[sec_name]["radix"],
                "known_value": _format_disp(old_disp, STRUCT_SECTIONS[sec_name]["radix"]),
                "anchored_sites": len(sites),
                "width_mix": width_mix(sites),
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

def _load_source_codemap(sigdb):
    """Best-effort CodeMap for the binary sigs.json was built from, so an
    UNCONFIRMED field's diagnostic can show the ORIGINAL site next to each
    new-binary candidate -- the same side-by-side "is this the same code
    shape" comparison known/2026-08-19.json's provenance describes doing by
    hand. Returns None quietly if the binary has moved, been deleted, or
    changed (sha256 mismatch) -- this is a nice-to-have, never a requirement.
    """
    meta = sigdb.get("meta", {})
    path = meta.get("source_binary")
    want_sha = meta.get("sha256", "").lower()
    if not path or not os.path.isfile(path):
        return None
    if want_sha and sha256(path).lower() != want_sha:
        return None
    try:
        return CodeMap(PEImage(path))
    except Exception:
        return None


def _default_review_path(out_ini):
    """Next to --out-ini if one was given, else the current directory --
    somewhere a person running `resolve` will actually look, without
    needing a flag for the common case.
    """
    if out_ini:
        return os.path.join(os.path.dirname(os.path.abspath(out_ini)), "eqoffsets_review.md")
    return "eqoffsets_review.md"


def _evaluate_struct_fields(image, sigdb, static, best_effort=False):
    """Apply the confirm / best-effort / fallback policy to every struct
    field, overlaying `static` in place, and return one result dict per
    field: {key, sec_name, field, label, radix, status, value, why,
    known_val, r, signatures}.

    `status` is "confirmed", "best_effort", or "unconfirmed". Shared by
    cmd_resolve (verbose reporting) and cmd_update (terse reporting, and
    never best_effort -- see cmd_update's own note) so the actual
    accept/fallback decision, and the data behind an UNCONFIRMED or
    BEST-EFFORT field's review report, can never drift between the two the
    way the old separately-maintained copies of this logic eventually would
    have.
    """
    struct_sigs = sigdb.get("struct_offsets", {})
    if not struct_sigs:
        return []
    struct_resolutions = resolve_struct_all(image, struct_sigs)

    results = []
    for key, entry in struct_sigs.items():
        sec_name = entry.get("section", "SpawnInfo Offsets")
        field = entry.get("field", key)
        radix = entry.get("radix", STRUCT_SECTIONS.get(sec_name, {}).get("radix", 16))
        signatures = entry.get("signatures", [])
        r = struct_resolutions.get(key)
        problems = validate_struct_offset(field, r.value if (r and r.ok) else None)
        known_val = static.get(sec_name, {}).get(field)
        label = f"{sec_name.split()[0]}.{field}"

        if r and r.ok and r.consistent and not problems:
            value = _format_disp(r.value, radix)
            status = "confirmed"
            if r.unanimous:
                why = "unanimous"
            elif r.discounted:
                why = (f"{r.agreement}/{r.agreement} on-width fired, no on-width dissent, "
                       f"{len(r.discounted)} off-width dissent discounted")
            else:
                why = f"{r.agreement}/{r.agreement} fired, no dissent"
            static.setdefault(sec_name, {})[field] = value
        elif best_effort and r and r.ok and not problems:
            value = _format_disp(r.value, radix)
            status = "best_effort"
            why = f"{r.agreement}/{len(r.votes)} agree -- NOT independently confirmed"
            static.setdefault(sec_name, {})[field] = value
        else:
            value = known_val if known_val is not None else "?"
            status = "unconfirmed"
            why = problems[0] if problems else (r.summary() if r else "no signatures")

        results.append({
            "key": key, "sec_name": sec_name, "field": field, "label": label,
            "radix": radix, "status": status, "value": value, "why": why,
            "known_val": known_val, "r": r, "signatures": signatures,
            "width_note": width_note(r, lambda v, _radix=radix: _format_disp(v, _radix)),
        })
    return results


def _field_review_report(res, codemap, old_codemap):
    """review.build_field_report for one _evaluate_struct_fields result.

    The one place resolve and update turn a result into a review report.
    Each used to make this call itself, and the copies drifted: the
    width-check advisory reached resolve's review doc but not update's --
    the doc most people actually open.
    """
    return build_field_report(res["label"], res["r"], res["radix"], res["signatures"],
                              _format_disp, codemap, old_codemap, res["known_val"],
                              res["status"], res["why"], applied_val=res["value"],
                              width_note=res["width_note"])


def _print_candidates(rep):
    """Console rendering of one review.build_field_report() dict -- kept in
    lockstep with the Markdown version because both read the same data.
    """
    for c in rep["candidates"]:
        print(f"      candidate {c['value_str']} ({len(c['sids'])} vote(s): "
              f"{', '.join(c['sids'])}), e.g. {c['rep']} [{c['anchor']}]")
        if c["old_window"]:
            print("          old binary, as originally derived:")
            for line in c["old_window"]:
                print(f"            {line}")
        if c["new_window"]:
            print("          this binary:")
            for line in c["new_window"]:
                print(f"            {line}")
        if not c["old_window"] and not c["new_window"]:
            print("          (could not recover disassembly context here)")


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
    # overlay any field this binary's own signatures confirm with no dissent.
    # A field that resolves but disagrees, or that has no signatures at all
    # (old sigs.json, or structsig couldn't anchor it), keeps the --known
    # value and is flagged as unverified rather than silently trusted --
    # unless --best-effort says to take the plurality anyway; see its help
    # text for the real, measured risk of that.
    static = {sec: dict(fields) for sec, fields in known.get("static_sections", {}).items()}
    struct_sigs = sigdb.get("struct_offsets", {})
    review_reports = []
    if struct_sigs:
        codemap = CodeMap(image)
        # Nice-to-have: lets the UNCONFIRMED diagnostic show each candidate's
        # ORIGINAL site next to its new-binary match, so a real side-by-side
        # comparison is possible instead of judging the new site in isolation.
        old_codemap = _load_source_codemap(sigdb)
        results = _evaluate_struct_fields(image, sigdb, static, best_effort=args.best_effort)
        print("\n--- struct member offsets (anchored derivation) ---")
        for res in results:
            label, radix, r, why = res["label"], res["radix"], res["r"], res["why"]
            if res["status"] == "confirmed":
                tag = ""
                if (res["known_val"] is not None
                        and str(res["known_val"]).lower() != res["value"].lower()):
                    tag = f"  (known-offsets had {res['known_val']} -- updating)"
                print(f"  {label}: {res['value']} [{why}]{tag}")
                # Discounted dissent is still dissent the reader is entitled
                # to see (CLAUDE.md invariant 5) -- it just no longer blocks.
                if res["width_note"]:
                    print(f"      {res['width_note']}")
                    for sid, w in r.discounted.items():
                        print(f"      - {sid}: voted {_format_disp(r.votes[sid], radix)}"
                              f"  <- discounted, {width_label(w)} access")
                continue

            rep = _field_review_report(res, codemap, old_codemap)
            review_reports.append(rep)
            if res["status"] == "best_effort":
                print(f"  {label}: {res['value']} [BEST-EFFORT, {why}]")
            else:
                print(f"  {label}: UNCONFIRMED ({why}) -- keeping known-offsets value "
                      f"{res['value']}")
                if r:
                    for sid, val in r.votes.items():
                        tag = "" if val == r.value else "  <- disagrees"
                        print(f"      - {sid}: voted {_format_disp(val, radix)}{tag}")
                    for sid, reason in r.failures.items():
                        print(f"      - {sid}: {reason}")
            if res["width_note"]:
                print(f"      {res['width_note']}")
            _print_candidates(rep)

        struct_undetermined = [res["label"] for res in results if res["status"] == "unconfirmed"]
        struct_best_effort = [res["label"] for res in results if res["status"] == "best_effort"]
        if struct_undetermined:
            print(f"unconfirmed struct field(s), carried forward unverified: "
                  f"{', '.join(struct_undetermined)}")
        if struct_best_effort:
            print(f"BEST-EFFORT struct field(s) applied without independent confirmation: "
                  f"{', '.join(struct_best_effort)} -- verify these by hand before trusting them")
        if review_reports:
            review_path = args.review_file or _default_review_path(args.out_ini)
            write_markdown(review_path, review_reports, meta={"binary": args.binary})
            print(f"wrote {review_path} -- candidate values and code for each field above, "
                  f"for manual review")

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
        struct_resolutions = resolve_struct_all(image, struct_sigs)
        known_static = known.get("static_sections", {})
        print("\n--- struct member offsets vs known-good ---")
        for key, entry in struct_sigs.items():
            sec_name = entry.get("section", "SpawnInfo Offsets")
            field = entry.get("field", key)
            want_str = known_static.get(sec_name, {}).get(field)
            if want_str is None:
                continue
            # [WorldInfo Offsets] is written in decimal; reading "10" as hex
            # here would report a correct derivation as a failure.
            radix = entry.get("radix", STRUCT_SECTIONS.get(sec_name, {}).get("radix", 16))
            want = _parse_disp(want_str, radix)
            shown = _format_disp
            r = struct_resolutions.get(key)
            label = f"{sec_name.split()[0]}.{field}"
            if r is None or not r.ok:
                print(f"  FAIL {label}: unresolved (expected {shown(want, radix)})")
                failed += 1
            elif r.value == want:
                tag = "" if r.consistent else f"  (SPLIT {r.agreement}/{len(r.votes)} voters)"
                print(f"  ok   {label}: {shown(r.value, radix)}{tag}")
                passed += 1
            else:
                print(f"  FAIL {label}: got {shown(r.value, radix)}, "
                      f"expected {shown(want, radix)}")
                failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------- crosscheck


def _sig_results(signatures, resolution, want):
    """Per-signature verdict for one offset at one patch boundary."""
    out = {}
    for sig in signatures:
        sid = sig.get("id", "?")
        if resolution and sid in resolution.votes:
            out[sid] = {
                "matched": True,
                "value": resolution.votes[sid],
                "correct": resolution.votes[sid] == want,
                "failure": None,
                "anchor": sig.get("anchor"),
            }
        else:
            out[sid] = {
                "matched": False,
                "value": None,
                "correct": False,
                "failure": (resolution.failures.get(sid) if resolution else None) or "unresolved",
                "anchor": sig.get("anchor"),
            }
    return out


def _check_pair(old_image, old_known_data, new_image, new_known_data, keep=5,
                struct_keep=9, structs=True):
    """Build sigs from old_image, resolve against new_image, compare to new_known_data.

    Returns a dict keyed by offset name -- memory offsets under their bare
    name, struct fields as "SpawnInfo.LevelOffset" -- each::

        {
          "expected": int,
          "got":      int | None,
          "passed":   bool,
          "unanimous": bool,
          "consistent": bool,
          "radix":    16 | 10,
          "sig_results": {
              sig_id: {"matched": bool, "value": int|None,
                       "correct": bool, "failure": str|None, "anchor": str|None}
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

    resolutions = resolve_all(new_image, {"offsets": sigs_by_offset})
    expected = {k: parse_addr(v) for k, v in new_known_data["memory_offsets"].items()}

    result = {}
    for name, want in expected.items():
        r = resolutions.get(name)
        result[name] = {
            "expected": want,
            "got": r.value if (r and r.ok) else None,
            "passed": r is not None and r.ok and r.value == want,
            "unanimous": r.unanimous if (r and r.ok) else False,
            "consistent": r.consistent if (r and r.ok) else False,
            "radix": 16,
            "sig_results": _sig_results(
                sigs_by_offset.get(name, {}).get("signatures", []), r, want),
        }

    # Struct member offsets get the same treatment: build anchored signatures
    # from the older binary, resolve them against the newer one, and score
    # each signature against the newer binary's published value. This is the
    # only way to tell an anchoring rule that works from one that merely
    # sounds convincing -- see anchor.py's calibration note.
    if not structs or not old_known_data.get("static_sections"):
        return result

    kinds, want_map, fields = _struct_plan(old_known_data)
    codemap = CodeMap(old_image)
    anchored = find_anchored_sites(old_image, kinds, want=want_map, codemap=codemap)
    new_static = new_known_data.get("static_sections", {})

    struct_sigs = {}
    for sec_name, field, old_disp in fields:
        sites = anchored.get(sec_name, {}).get(old_disp, [])
        sigs = signatures_from_sites(old_image, field, sites, codemap=codemap,
                                     keep=struct_keep, verbose=False)
        struct_sigs[_struct_key(sec_name, field)] = {
            "section": sec_name, "field": field,
            "radix": STRUCT_SECTIONS[sec_name]["radix"], "signatures": sigs,
            "width_mix": width_mix(sites),
        }

    struct_res = resolve_struct_all(new_image, struct_sigs)
    for key, entry in struct_sigs.items():
        sec_name, field = entry["section"], entry["field"]
        want_str = new_static.get(sec_name, {}).get(field)
        if want_str is None:
            continue
        radix = entry["radix"]
        want = _parse_disp(want_str, radix)
        r = struct_res.get(key)
        result[f"{sec_name.split()[0]}.{field}"] = {
            "expected": want,
            "got": r.value if (r and r.ok) else None,
            "passed": r is not None and r.ok and r.value == want,
            "unanimous": r.unanimous if (r and r.ok) else False,
            "consistent": r.consistent if (r and r.ok) else False,
            "radix": radix,
            "discounted": dict(r.discounted) if r else {},
            "sig_results": _sig_results(entry["signatures"], r, want),
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
    # anchor_survival[anchor_kind] = {"tested": N, "passed": N}. This is the
    # number that decides which anchoring rules earn their keep; see the
    # calibration note in anchor.py.
    anchor_survival = {}
    boundary_records = []
    any_failed = False

    for from_date, to_date in boundaries:
        print(f"--- {from_date} -> {to_date} ---")
        old_image = open_image(binary_dates[from_date])
        old_known = load_json(known_dates[from_date])
        new_image = open_image(binary_dates[to_date])
        new_known = load_json(known_dates[to_date])

        print("  building signatures from older binary...")
        pair = _check_pair(old_image, old_known, new_image, new_known,
                           keep=args.keep, struct_keep=args.struct_keep,
                           structs=not args.no_structs)

        passed_n = failed_n = 0
        for name, entry in pair.items():
            radix = entry.get("radix", 16)
            want = entry["expected"]
            got = entry["got"]
            if entry["passed"]:
                tag = "" if entry["consistent"] else "  [SPLIT]"
                if entry.get("discounted"):
                    tag += f"  [{len(entry['discounted'])} off-width dissent discounted]"
                print(f"    ok   {name}: {_format_disp(got, radix)}{tag}")
                passed_n += 1
            else:
                got_str = _format_disp(got, radix) if got is not None else "unresolved"
                print(f"    FAIL {name}: got {got_str}, expected {_format_disp(want, radix)}")
                failed_n += 1
                any_failed = True
            for sid, sr in entry["sig_results"].items():
                if not sr["correct"]:
                    reason = sr["failure"] or (
                        f"voted {_format_disp(sr['value'], radix)}"
                        if sr["value"] is not None else "no match"
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
                anchor = sr.get("anchor") or "rip_global"
                arec = anchor_survival.setdefault(
                    anchor, {"tested": 0, "matched": 0, "passed": 0})
                arec["tested"] += 1
                arec["matched"] += bool(sr["matched"])
                arec["passed"] += bool(sr["correct"])

        # Serialisable boundary record (ints -> strings in the section's radix).
        boundary_records.append({
            "from": from_date,
            "to": to_date,
            "offsets": {
                name: {
                    "expected": _format_disp(entry["expected"], entry.get("radix", 16)),
                    "got": (_format_disp(entry["got"], entry.get("radix", 16))
                            if entry["got"] is not None else None),
                    "passed": entry["passed"],
                    "unanimous": entry["unanimous"],
                    "consistent": entry["consistent"],
                    "discounted": entry.get("discounted", {}),
                    "sig_results": {
                        sid: {
                            "matched": sr["matched"],
                            "value": (_format_disp(sr["value"], entry.get("radix", 16))
                                      if sr["value"] is not None else None),
                            "correct": sr["correct"],
                            "failure": sr["failure"],
                            "anchor": sr.get("anchor"),
                        }
                        for sid, sr in entry["sig_results"].items()
                    },
                }
                for name, entry in pair.items()
            },
        })

    # Print survival matrix.
    print("=== survival matrix ===")
    print(f"  {'offset':<28} {'sig':<24} {'tested':>6} {'passed':>6} {'rate':>6}")
    print("  " + "-" * 74)
    for offset_name in sorted(survival):
        for sig_id, stats in sorted(survival[offset_name].items()):
            t, p = stats["tested"], stats["passed"]
            rate = f"{100 * p // t}%" if t else "n/a"
            print(f"  {offset_name:<28} {sig_id:<24} {t:>6} {p:>6} {rate:>6}")

    if anchor_survival:
        # Two separate numbers on purpose. A signature that stopped matching
        # is attrition -- the code around it changed -- and costs you evidence.
        # A signature that matched and voted wrong is an anchoring mistake and
        # costs you a wrong answer. Only the second column condemns a rule.
        print("\n=== survival by anchor kind ===")
        print(f"  {'anchor':<12} {'fired':>12} {'right when fired':>18}")
        for anchor, stats in sorted(anchor_survival.items(),
                                    key=lambda kv: -kv[1]["tested"]):
            t, m, p = stats["tested"], stats["matched"], stats["passed"]
            fired = f"{m}/{t} ({100 * m // t}%)" if t else "n/a"
            right = f"{p}/{m} ({100 * p // m}%)" if m else "n/a"
            print(f"  {anchor:<12} {fired:>12} {right:>18}")

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
        "anchor_survival": {
            a: {**s, "rate": s["passed"] / s["tested"] if s["tested"] else 0.0}
            for a, s in anchor_survival.items()
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


def _struct_changes(ini_cp, struct_results):
    """[(result, old_value_or_None)] for struct fields the new ini will change.

    update's replace prompt is the last moment a person can catch a bad
    value, so it has to show the struct fields too, not just the memory
    addresses -- on 10/19/2026 OwnerIDOffset and HideOffset both moved, and
    the old summary listed neither. Unconfirmed fields are included: a
    carried-forward value can still differ from what the ini has (it comes
    from the bundled known-offsets file, not from the user's old ini), and
    that change deserves the loudest label, not silence.
    """
    changes = []
    for res in struct_results:
        sec = res["sec_name"]
        cur = ini_cp[sec].get(res["field"]) if ini_cp.has_section(sec) else None
        if cur is None or _norm_value(cur) != _norm_value(res["value"]):
            changes.append((res, cur))
    return changes


_STATUS_LABEL = {
    "confirmed": "confirmed",
    "selected": "selected by you",
    "unconfirmed": "UNVERIFIED, carried forward -- see review doc",
}


def _ask(ask, prompt):
    """input() that treats a closed stdin as an empty answer, so piping
    update into something non-interactive falls back to the defaults
    instead of crashing halfway through."""
    try:
        return ask(prompt).strip()
    except EOFError:
        return ""


def _choose_field_value(res, rep, static, ask=input, say=print):
    """Let the user pick one UNCONFIRMED field's value from its candidates.

    Shows exactly what the review doc shows -- `rep` is the same
    build_field_report dict -- but numbered, so the choice is one keystroke
    instead of an edit to a known-offsets file. Each candidate carries how
    many of the field's signatures matched at that value in the new binary:
    that count is the tool's evidence, and a person overriding the tool
    should see how much of it they are overriding. The current value is
    always the last option and the default, so Enter changes nothing.

    Returns True if the user picked a value (which is then applied to
    `static` and marks `res` "selected"), False if they kept the current one.
    """
    n_sigs = len(res["signatures"])
    current = res["value"]
    say(f"\n{res['label']}  (currently {current}, carried forward -- not confirmed)")
    if res["width_note"]:
        say(f"  width check: {res['width_note']}")

    options = []
    for c in rep["candidates"]:
        options.append(c)
        same = ("  (same as the current value)"
                if _norm_value(c["value_str"]) == _norm_value(current) else "")
        say(f"  [{len(options)}] {c['value_str']} -- {len(c['sids'])} of {n_sigs} "
            f"signature(s) matched with this value in the new binary "
            f"[{c['anchor']} anchor]{same}")
        if c["old_window"]:
            say("        old binary, where the signature was built:")
            for line in c["old_window"]:
                say(f"          {line}")
        if c["new_window"]:
            say("        new binary, where it matched now:")
            for line in c["new_window"]:
                say(f"          {line}")
    if rep["failures"]:
        say(f"  ({len(rep['failures'])} of {n_sigs} signature(s) found no match at all "
            f"in the new binary)")
    keep = len(options) + 1
    say(f"  [{keep}] keep {current}")

    while True:
        raw = _ask(ask, f"  use which value for {res['label']}? "
                        f"[1-{keep}, Enter = keep {current}]: ")
        if raw == "" or raw == str(keep):
            return False
        if not (raw.isdigit() and 1 <= int(raw) < keep):
            say(f"  enter a number from 1 to {keep}, or just press Enter to keep {current}")
            continue
        # A hand-picked value is still an emitted value (CLAUDE.md invariant
        # 4): a candidate can be nonsense -- a sign-extended disp8 reads back
        # negative -- and picking it by number must not skip the check.
        problems = validate_struct_offset(res["field"], options[int(raw) - 1]["value"])
        if not problems:
            break
        say(f"  can't use that one: {problems[0]}")

    chosen = options[int(raw) - 1]["value_str"]
    static.setdefault(res["sec_name"], {})[res["field"]] = chosen
    res["value"] = chosen
    res["status"] = "selected"
    say(f"  -> {res['label']} = {chosen}")
    return True


def _offer_manual_selection(unconfirmed, reports, static, ask=input, say=print):
    """Ask once whether to hand-pick UNCONFIRMED fields; no means no change.

    Answering no (or anything but y, or a closed stdin) leaves update
    behaving exactly as it always has: carried-forward values, labeled
    UNVERIFIED, with the review doc to settle them later.
    """
    answer = _ask(ask, f"\n{len(unconfirmed)} field(s) could not be confirmed automatically. "
                       f"Choose their values yourself now? [y/N]: ").lower()
    if answer != "y":
        return 0
    picked = 0
    for res, rep in zip(unconfirmed, reports):
        picked += _choose_field_value(res, rep, static, ask=ask, say=say)
    return picked


def _update_summary_lines(existing, memory, struct_results):
    """The offset lines update shows before asking to write the ini.

    `existing` is the current ini (a ConfigParser), or None on a first run.
    Updating, the lines are a diff: every memory address with the ones that
    moved flagged, and only the struct fields whose value changes. Creating,
    there is nothing to diff against -- flagging all 37 values as "changed"
    buried the one thing a first-time user needs to see -- so memory
    addresses are listed plainly and struct fields are summarized, with any
    UNVERIFIED one still listed by name.
    """
    lines = []
    if existing is None:
        for n, v in memory.items():
            lines.append(f"  {n} = 0x{v:X}")
        flagged = [res for res in struct_results if res["status"] != "confirmed"]
        for res in flagged:
            lines.append(f"  {res['label']} = {res['value']}  <- {_STATUS_LABEL[res['status']]}")
        if struct_results:
            counts = {}
            for res in flagged:
                counts[res["status"]] = counts.get(res["status"], 0) + 1
            note = "".join(f", {counts[st]} {word}" for st, word in
                           (("selected", "selected by you"), ("unconfirmed", "unverified"))
                           if st in counts)
            if flagged:
                note += " (listed above)"
            lines.append(f"  ({len(struct_results)} struct field(s): "
                         f"{len(struct_results) - len(flagged)} confirmed{note})")
        return lines

    old_memory = existing["Memory Offsets"] if existing.has_section("Memory Offsets") else {}
    for n, v in memory.items():
        tag = "" if n in old_memory and _norm_value(old_memory[n]) == v else "  <- changed"
        lines.append(f"  {n} = 0x{v:X}{tag}")
    changes = _struct_changes(existing, struct_results)
    for res, old in changes:
        was = f"from {old}" if old is not None else "(missing from current ini)"
        lines.append(f"  {res['label']} = {res['value']}  <- changed {was}, "
                     f"{_STATUS_LABEL[res['status']]}")
    if struct_results:
        lines.append(f"  ({len(struct_results) - len(changes)} other struct field(s) unchanged)")
    return lines


def _remembered_path(cli_value, remembered_value, check, what):
    """cli_value wins if given (and becomes the new remembered value); else
    fall back to a remembered path from config.py, but only if it still
    checks out -- a stale remembered path (moved install, reinstalled game)
    must not be trusted silently. Returns (path_or_None, came_from_prompt).
    """
    if cli_value:
        return cli_value, False
    if remembered_value and check(remembered_value):
        return remembered_value, False
    if remembered_value:
        print(f"  (remembered {what} no longer exists, asking again: {remembered_value})")
    return None, True


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

    # --exe/--myseq-dir always override; otherwise fall back to whatever was
    # remembered from a previous run, and only prompt if there's nothing
    # usable either way. Whatever we end up with gets (re-)saved below, so
    # an override on the command line becomes the new default for next time
    # without needing to edit the config file by hand.
    remembered = pathconfig.load(args.config)
    exe_path, ask_exe = _remembered_path(
        args.exe, remembered.get("exe_path"), os.path.isfile, "eqgame.exe path")
    if ask_exe:
        exe_path = _prompt_existing_path("Path to your eqgame.exe: ", "file")
    if not exe_path:
        print("cancelled")
        return 1

    myseq_dir, ask_dir = _remembered_path(
        args.myseq_dir, remembered.get("myseq_dir"), os.path.isdir, "MySEQ folder")
    if ask_dir:
        myseq_dir = _prompt_existing_path(
            "Path to your MySEQ install folder (where myseqserver.ini lives): ", "dir")
    if not myseq_dir:
        print("cancelled")
        return 1

    pathconfig.save({"exe_path": exe_path, "myseq_dir": myseq_dir}, args.config)
    print(f"eqgame.exe : {exe_path}")
    print(f"MySEQ dir  : {myseq_dir}")
    print(f"  (remembered in {args.config} -- pass --exe/--myseq-dir to point elsewhere, "
          f"or delete that file to be asked again)\n")

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
    struct_results = _evaluate_struct_fields(image, sigdb, static, best_effort=False)
    confirmed = [res for res in struct_results if res["status"] == "confirmed"]
    unconfirmed = [res for res in struct_results if res["status"] == "unconfirmed"]

    if struct_results:
        print(f"struct member offsets: {len(confirmed)}/{len(struct_results)} "
              f"confirmed against this binary")
    review_path = None
    if unconfirmed:
        labels = [res["label"] for res in unconfirmed]
        print(f"carried forward unverified: {', '.join(labels)}")
        for res in unconfirmed:
            if res["width_note"]:
                print(f"  {res['label']}: {res['width_note']}")
        codemap = CodeMap(image)
        old_codemap = _load_source_codemap(sigdb)
        reports = [_field_review_report(res, codemap, old_codemap) for res in unconfirmed]
        review_path = os.path.join(myseq_dir, "eqoffsets_review.md")
        write_markdown(review_path, reports, meta={"binary": exe_path})
        print(f"see {review_path} for the candidate values and code to check by hand")
        if not args.yes:
            _offer_manual_selection(unconfirmed, reports, static)

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

    print(f"\n{'updating' if have_existing else 'creating'} {ini_path}:")
    print(f"  PatchDate   -> {patch_date}")
    print(f"  ClientHash  -> {bhash}")
    print(f"  BuildString -> {bstring}")
    port_note = "kept from existing config" if have_existing else "default, no existing config found"
    print(f"  port        -> {port}  ({port_note})")
    for line in _update_summary_lines(existing if have_existing else None,
                                      memory, struct_results):
        print(line)

    if not args.yes:
        verb = "Replace" if have_existing else "Write"
        answer = input(f"\n{verb} myseqserver.ini now? [y/N]: ").strip().lower()
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
    b.add_argument("--struct-keep", type=int, default=9,
                    help="signatures kept per struct field. Higher than --keep on "
                         "purpose: struct fields have many more anchored sites than "
                         "a global has reference sites, and a wider vote is what "
                         "separates a real layout change from one stale fingerprint")
    b.add_argument("--no-structs", action="store_true",
                    help="skip anchored struct-member offset derivation (globals only)")
    b.add_argument("--struct-shape-anchor", action="store_true",
                    help="also trust registers a function uses with several known "
                         "field offsets. Measured at 82%% cross-patch survival against "
                         "95-100%% for dataflow anchors, and it fails by claiming moved "
                         "fields stayed put -- only worth it if a field loses its "
                         "dataflow anchors entirely (see anchor.py)")
    b.set_defaults(func=cmd_build)

    r = sub.add_parser("resolve", help="apply signatures to a new binary")
    r.add_argument("--binary", required=True)
    r.add_argument("--sigs", default="sigs.json")
    r.add_argument("--out-ini")
    r.add_argument("--known", help="known-offsets file: fallback/baseline for struct-member "
                                    "offsets that can't be independently confirmed this run")
    r.add_argument("--patch-date")
    r.add_argument("--force", action="store_true")
    r.add_argument("--best-effort", action="store_true",
                    help="for struct fields that fail to confirm (no dissent), take the "
                         "raw plurality vote instead of falling back to --known. Off by "
                         "default because it is a measured real risk, not a hedge: across "
                         "the two boundaries in crosscheck_report.json, every wrong vote "
                         "traced to the weakest (linkseed) anchor tier, and in one real "
                         "case (SpawnInfo.HideOffset, 08/19->09/11/2026) the plurality was "
                         "outright wrong -- 2 stale votes outvoted the 1 correct one. Applied "
                         "fields are labeled BEST-EFFORT in the console output and listed "
                         "again in a final summary line, never silently merged into the "
                         "confirmed report; the value still lands in the INI (MySEQ's ini "
                         "format has no comment convention to flag it there), so read the "
                         "summary line before trusting one. The disassembly shown for each "
                         "candidate is there so you can override the vote yourself.")
    r.add_argument("--review-file",
                    help="where to write the manual-review Markdown doc for any "
                         "UNCONFIRMED/BEST-EFFORT struct field (default: next to "
                         "--out-ini, or ./eqoffsets_review.md if --out-ini wasn't given). "
                         "Not written at all if every struct field confirmed cleanly.")
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
    cc.add_argument("--struct-keep", type=int, default=9)
    cc.add_argument("--no-structs", action="store_true",
                    help="only cross-check the RIP-relative globals")
    cc.set_defaults(func=cmd_crosscheck)

    u = sub.add_parser("update",
                       help="interactively point at eqgame.exe + a MySEQ install and "
                            "write a corrected myseqserver.ini in place")
    u.add_argument("--exe", help="path to eqgame.exe -- overrides any remembered path "
                                  "for this run AND becomes the new remembered one")
    u.add_argument("--myseq-dir", help="MySEQ install folder -- same override/remember "
                                        "behavior as --exe")
    u.add_argument("--config", default=pathconfig.DEFAULT_PATH,
                    help=f"where --exe/--myseq-dir are remembered between runs "
                         f"(default: {pathconfig.DEFAULT_PATH})")
    u.add_argument("--known-dir", default="known")
    u.add_argument("--sigs-dir", default="sigs")
    u.add_argument("--yes", action="store_true", help="skip the replace confirmation prompt")
    u.set_defaults(func=cmd_update)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
