"""Derive struct member displacement offsets (extract: "insn_disp").

Same idea as sigbuild.py -- find instructions that reference a known value,
strip the bytes that encode the value, keep the rest as a fingerprint -- but
applied to a ModRM displacement instead of a RIP-relative global. This is
what fills in `[SpawnInfo Offsets]`, `[GroundItem Offsets]` and
`[WorldInfo Offsets]` instead of copying them forward from last patch's file
and hoping the struct did not get reorganised. (It does get reorganised: the
07/17 -> 08/19/2026 patch moved six SpawnInfo fields, and the first symptom
was every spawn on the map reporting level 48.)

Deciding *which* sites are allowed to contribute is the whole problem, and
it lives in anchor.py -- read that module's docstring first. This file
assumes it has been handed sites that are already anchored and only has to
turn each one into a byte pattern.

Wildcarding
-----------
sigbuild.py deliberately keeps non-RIP displacements concrete, because a
struct offset is a stable, highly selective constant. Here that constant is
precisely what we are trying to read, so the *site's own* displacement is
wildcarded -- and nothing else's is. Every other instruction in the window
keeps its displacements intact, which is what stops these patterns from
degenerating into something that matches half the binary.

Encoding note
-------------
The compiler packs small displacements into one byte (`disp8`) and larger
ones into four (`disp32`), so the site's `disp_size` is recorded with the
signature and resolve.py reads back exactly that many bytes, sign-extended.
A field that crosses the 0x7f boundary between two patches changes its
instruction *length*, so the pattern stops matching entirely and the field
is reported unresolved. That is the correct outcome: the signature has
genuinely lost track of the field, and saying so beats reading a byte out of
the middle of some other instruction.
"""

from .codemap import CodeMap
from .anchor import StructKind, find_anchored_sites, ANCHOR_STRENGTH
from .sigbuild import MAX_WINDOW_INSNS, MIN_SIG_BYTES, MIN_ANCHOR_BYTES, _wildcard_ranges
from .scan import format_pattern, compile_pattern, find_all

# Building a signature means scanning .text for uniqueness, so the candidate
# pool is capped. Sites are tried strongest-anchor-first, so the cap only
# ever discards the least trustworthy tail.
MAX_CANDIDATE_SITES = 120


def _window(image, md, sec, site, max_insns=MAX_WINDOW_INSNS):
    """Grow a wildcarded pattern forward from `site`, yielding each length.

    The site instruction's own displacement is wildcarded (it is the value we
    want to read back); every later instruction is wildcarded by the same
    address-only rules sigbuild uses.
    """
    start = site.va - sec.va
    chunk = sec.data[start:start + max_insns * 16 + 16]
    pat = bytearray()
    mask = []
    site_disp_off = site_disp_size = None

    for idx, insn in enumerate(md.disasm(chunk, site.va, count=max_insns)):
        base = len(pat)
        pat.extend(insn.bytes)
        mask.extend("x" * insn.size)
        if idx == 0:
            site_disp_off = insn.encoding.disp_offset
            site_disp_size = insn.encoding.disp_size
            if not site_disp_size:
                return      # nothing to extract from a bare [reg] access
            for k in range(site_disp_size):
                mask[base + site_disp_off + k] = "?"
        else:
            for off, size in _wildcard_ranges(image, insn):
                for k in range(size):
                    if 0 <= base + off + k < len(mask):
                        mask[base + off + k] = "?"
        yield bytes(pat), "".join(mask), site_disp_off, site_disp_size


def build_signature_for_site(image, md, sec, site, text_sections):
    """Shortest unique signature anchored at `site`, extracting its own disp."""
    for pat, mask, disp_off, disp_size in _window(image, md, sec, site):
        if len(pat) < MIN_SIG_BYTES:
            continue
        pattern_text = format_pattern(pat, mask)
        compiled = compile_pattern(pattern_text)
        if compiled.anchor_len < MIN_ANCHOR_BYTES:
            continue

        total = 0
        for s in text_sections:
            total += len(find_all(s.data, compiled, limit=2))
            if total > 1:
                break
        if total != 1:
            continue

        return {
            "pattern": pattern_text,
            "extract": "insn_disp",
            "disp_off": disp_off,
            "disp_size": disp_size,
            "site_va": f"0x{site.va:X}",
            "insn": site.text,
            "anchor": site.anchor,
            "width": site.width,
            "length": len(pat),
            "wildcards": mask.count("?"),
            "anchor_len": compiled.anchor_len,
        }
    return None


def score_signature(sig):
    """Higher is better.

    How the site was anchored dominates: a pattern built on a register traced
    straight out of CharInfo is worth more than an equally tidy pattern built
    on a register that merely looked like it was walking a linked list. After
    that the same shape-of-the-pattern reasoning as sigbuild.score_signature
    applies -- long concrete runs are selective, wildcards and length are
    not.

    The non-anchor weights are deliberately left identical to
    sigbuild.score_signature. One patch boundary does show long patterns
    surviving worse (80% at 32+ bytes against 100% below that), but raising
    the length penalty to 0.5 or 1.0 and re-measuring just moved which single
    GroundItem field split -- it did not reduce disagreement. That is noise at
    this sample size, and fitting to it would be exactly the premature
    calibration CLAUDE.md task 2 warns against. Revisit once crosscheck has
    more than one boundary to fit against.
    """
    score = ANCHOR_STRENGTH.get(sig.get("anchor"), 0) * 10.0
    score += min(sig["anchor_len"], 16) * 2.0
    score -= (sig["wildcards"] / max(sig["length"], 1)) * 20.0
    score -= sig["length"] * 0.15
    return round(score, 3)


def signatures_from_sites(image, field_name, sites, codemap=None, keep=5,
                          max_sites=MAX_CANDIDATE_SITES, verbose=True):
    """Turn anchored sites for one field into its best `keep` signatures."""
    codemap = codemap or CodeMap(image)
    md = codemap.md
    text_sections = image.exec_sections()

    candidates = [s for s in sites if s.disp_size][:max_sites]
    sigs = []
    for site in candidates:
        sec = image.section_for_va(site.va)
        if sec is None:
            continue
        sig = build_signature_for_site(image, md, sec, site, text_sections)
        if sig:
            sig["score"] = score_signature(sig)
            sigs.append(sig)

    sigs.sort(key=lambda s: s["score"], reverse=True)
    sigs = sigs[:keep]
    for i, s in enumerate(sigs):
        s["id"] = f"{field_name}#{i}"

    if verbose:
        mix = {}
        for s in sigs:
            mix[s["anchor"]] = mix.get(s["anchor"], 0) + 1
        mix_text = ", ".join(f"{k}:{v}" for k, v in sorted(mix.items())) or "none"
        print(f"  {field_name}: {len(sites)} anchored site(s) -> "
              f"kept {len(sigs)} signature(s) [{mix_text}]")
        if sites and not sigs:
            print(f"  {field_name}: WARNING every anchored site was ambiguous or too short")
        if not sites:
            print(f"  {field_name}: no anchored site -- refusing to guess")

    return sigs


def width_mix(sites):
    """{width: site count} over a field's *whole* anchored pool.

    Recorded at build time so resolve.py can tell a dissenting vote that
    touches the field the way the field is normally touched from one that
    does not (resolve.apply_width_rule). It has to be the whole pool, not
    the handful of kept signatures: on SpawnInfo.HideOffset at 08/19/2026
    the kept signatures were two 2-byte reads (both wrong) and one 4-byte
    read (right), so a majority taken among them would have picked the
    wrong width and thrown away the only correct vote. The pool -- 10
    4-byte sites against 8 2-byte ones -- did not make that mistake.
    """
    mix = {}
    for site in sites:
        mix[site.width] = mix.get(site.width, 0) + 1
    return mix


def build_struct_offset_signatures(image, name, old_disp, safe_disps, trusted_globals,
                                   keep=5, max_sites=MAX_CANDIDATE_SITES, verbose=True,
                                   enable_shape=False):
    """Single-field convenience wrapper: anchor, then build.

    Kept for callers that only have one displacement in hand. It runs a whole
    anchoring pass per call, so cli.py uses the batched path instead --
    `find_anchored_sites` once for every field, then `signatures_from_sites`
    per field.
    """
    codemap = CodeMap(image)
    kind = StructKind(name="struct", root_globals=trusted_globals,
                      link_disps=safe_disps, field_disps=())
    anchored = find_anchored_sites(image, [kind], want={"struct": {old_disp}},
                                   codemap=codemap, enable_shape=enable_shape)
    sites = anchored.get("struct", {}).get(old_disp, [])
    return signatures_from_sites(image, name, sites, codemap=codemap,
                                 keep=keep, max_sites=max_sites, verbose=verbose)
