"""Derive struct member displacement offsets (extract: "insn_disp").

This is the same idea as sigbuild.py -- find instructions that reference a
known value, strip the address-carrying bytes, keep the rest as a
fingerprint -- but applied to a ModRM displacement instead of a RIP-relative
global. It exists to auto-derive fields like LevelOffset/ClassOffset/
HideOffset in [SpawnInfo Offsets], which build/resolve previously just
copied verbatim from the known-offsets file every patch (see README "Known
limits" -- or rather, see its history, since this module is what closed that
gap).

ANCHORING -- read this before touching the anchoring rules below
------------------------------------------------------------------
A struct member offset is a small integer, not part of a unique address. A
bare search for "every instruction that touches [reg+0x564]" turns up every
class in an 8 MB .text section that happens to have an unrelated field at
that same numeric offset -- there is no way to tell those apart by bytes
alone. This is not hypothetical: an early manual pass at deriving
HideOffset (0x4d0) for the 08/19/2026 patch picked a site that was
byte-identical across the patch and looked like solid evidence, and it was
wrong -- it was a qword store in a completely unrelated, unmodified
function that simply happened to share the same struct offset. A published
offset list caught it. See known/2026-08-19.json's _provenance for the full
story.

So a candidate site is only trusted if it is *anchored*: we can show, by
looking a few instructions back (bounded to the same function via a run of
0xCC padding, which is how MSVC pads between functions in this binary),
that its base register was actually derived from something already known to
point at a spawn:

  * dereferenced through one of the caller-supplied `safe_disps` -- normally
    NextOffset/PrevOffset, the linked-list pointers, which are small,
    ubiquitous, and have survived every patch boundary observed so far
    (crosscheck_report.json), or
  * the surrounding code contains a RIP-relative reference to one of the
    caller-supplied `trusted_globals` -- normally the already-resolved
    SpawnHeaderAddr/CharInfo addresses.

Unanchored sites are discarded before a signature is ever built for them --
they do not get to vote, not even as a minority. If nothing anchors, the
field comes back with zero signatures and build/resolve report it as
undetermined rather than emitting a guess. That is the same "never emit an
unvalidated address" rule the rest of this project follows, applied one
level below the address itself.

SCOPE
-----
Only ModRM disp32 encodings are searched (matches sigbuild's own note that
non-RIP displacements are never wildcarded -- here we WANT the displacement,
so we wildcard it deliberately, but only when the compiler encoded it as a
full 4-byte displacement). Small offsets the compiler packed into a single
disp8 byte (roughly anything under 0x80, e.g. NextOffset/XOffset/YOffset)
are not found by this scan -- disp8 values are one byte wide and appear
constantly throughout any binary, so a byte-level search for them is both
slow and far too noisy to anchor reliably. Those fields still have to be
carried forward by hand. See README for the current field-by-field status.
"""

from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from .refs import make_disassembler, rip_target
from .sigbuild import MAX_WINDOW_INSNS, MIN_SIG_BYTES, MIN_ANCHOR_BYTES, _wildcard_ranges
from .scan import format_pattern, compile_pattern, find_all

import struct

MAX_BACKWARD_BYTES = 0x800
MAX_BACKWARD_INSNS = 40

# x86-64 GPRs grouped by family (same register, different operand widths) so
# an anchor check on e.g. "rcx" also recognizes "ecx"/"cx"/"cl" as the same
# register. Capstone gives each width its own X86_REG_* constant with no
# built-in family lookup, so we build one from the (regular) name pattern.
_REG_FAMILIES = [
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
    ("r8", "r8d", "r8w", "r8b"),
    ("r9", "r9d", "r9w", "r9b"),
    ("r10", "r10d", "r10w", "r10b"),
    ("r11", "r11d", "r11w", "r11b"),
    ("r12", "r12d", "r12w", "r12b"),
    ("r13", "r13d", "r13w", "r13b"),
    ("r14", "r14d", "r14w", "r14b"),
    ("r15", "r15d", "r15w", "r15b"),
]
_REG_FAMILY_BY_NAME = {name: i for i, fam in enumerate(_REG_FAMILIES) for name in fam}


def _reg_family(md, reg_id):
    if not reg_id:
        return None
    return _REG_FAMILY_BY_NAME.get(md.reg_name(reg_id))


class DispSite:
    __slots__ = ("va", "size", "disp_off", "disp_size", "base_reg", "section", "text")

    def __init__(self, va, size, disp_off, disp_size, base_reg, section, text):
        self.va = va
        self.size = size
        self.disp_off = disp_off
        self.disp_size = disp_size
        self.base_reg = base_reg
        self.section = section
        self.text = text

    def __repr__(self):
        return f"<DispSite 0x{self.va:X} {self.text}>"


def find_disp32_sites(image, md, sections, disp_value, max_sites=None):
    """Every instruction referencing [reg+disp_value] on a non-RIP base register."""
    needle = struct.pack("<i", disp_value)
    found = []
    for sec in sections:
        data = sec.data
        start = 0
        while True:
            p = data.find(needle, start)
            if p == -1:
                break
            start = p + 1
            for s in range(max(0, p - 8), p - 1):
                chunk = data[s:s + 16]
                insn = next(md.disasm(chunk, sec.va + s, count=1), None)
                if insn is None:
                    continue
                if insn.encoding.disp_size != 4 or insn.encoding.disp_offset != p - s:
                    continue
                if s + insn.size <= p + 3:
                    continue
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.disp == disp_value and op.mem.base != X86_REG_RIP:
                        found.append(DispSite(
                            va=insn.address, size=insn.size,
                            disp_off=insn.encoding.disp_offset, disp_size=insn.encoding.disp_size,
                            base_reg=op.mem.base, section=sec.name,
                            text=f"{insn.mnemonic} {insn.op_str}".strip(),
                        ))
                        break
                break
            if max_sites and len(found) >= max_sites:
                return found
    return found


def _instructions_before(md, sec, site_va, max_back=MAX_BACKWARD_BYTES, max_insns=MAX_BACKWARD_INSNS):
    """Best-effort instruction list immediately preceding site_va, bounded to
    (best guess) the same function. Returns [] if alignment can't be
    recovered cleanly -- callers must treat that as "no anchor found", not
    as license to assume one.
    """
    site_off = site_va - sec.va
    data = sec.data
    lo = max(0, site_off - max_back)
    bound = lo
    i = site_off
    while i > lo:
        if data[i - 1] == 0xCC:
            bound = i
            break
        i -= 1

    for start in range(bound, min(bound + 8, site_off + 1)):
        insns = []
        chunk = data[start:site_off + 16]
        aligned = False
        for insn in md.disasm(chunk, sec.va + start):
            if insn.address >= site_va:
                aligned = insn.address == site_va
                break
            insns.append(insn)
        if aligned:
            return insns[-max_insns:]
    return []


def is_anchored(md, sec, site, safe_disps, trusted_globals):
    """Return (bool, reason) -- see module docstring for what "anchored" means."""
    insns = _instructions_before(md, sec, site.va)
    if not insns:
        return False, "could not recover instruction alignment before the site"

    target_family = _reg_family(md, site.base_reg)
    reg_shadowed = False
    for insn in reversed(insns):
        t = rip_target(insn)
        if t is not None and t in trusted_globals:
            return True, f"nearby reference to trusted global 0x{t:X} at 0x{insn.address:X}"

        if not reg_shadowed and target_family is not None and insn.operands:
            dst = insn.operands[0]
            if dst.type == X86_OP_REG and _reg_family(md, dst.reg) == target_family:
                safe_deref = any(
                    op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP and op.mem.disp in safe_disps
                    for op in insn.operands
                )
                if safe_deref:
                    return True, f"base register loaded via a known-safe offset at 0x{insn.address:X}"
                # The register's most recent definition wasn't a safe deref,
                # so an older one doesn't tell us anything -- it's shadowed.
                reg_shadowed = True

    return False, "no known-safe dereference or trusted global reference nearby"


def _window(image, md, sec, site_va, max_insns=MAX_WINDOW_INSNS):
    start = site_va - sec.va
    chunk = sec.data[start:start + max_insns * 16 + 16]
    pat = bytearray()
    mask = []
    for idx, insn in enumerate(md.disasm(chunk, site_va, count=max_insns)):
        base = len(pat)
        pat.extend(insn.bytes)
        mask.extend("x" * insn.size)
        if idx == 0:
            off, size = insn.encoding.disp_offset, insn.encoding.disp_size
            for k in range(size):
                mask[base + off + k] = "?"
            site_disp_off, site_disp_size = off, size
        else:
            for off, size in _wildcard_ranges(image, insn):
                for k in range(size):
                    if 0 <= base + off + k < len(mask):
                        mask[base + off + k] = "?"
        yield bytes(pat), "".join(mask), site_disp_off, site_disp_size


def build_signature_for_site(image, md, sec, site, text_sections):
    """Shortest unique signature anchored at `site`, extracting its own disp."""
    for pat, mask, disp_off, disp_size in _window(image, md, sec, site.va):
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
            "length": len(pat),
            "wildcards": mask.count("?"),
            "anchor_len": compiled.anchor_len,
        }
    return None


def score_signature(sig):
    score = 0.0
    score += min(sig["anchor_len"], 16) * 2.0
    score -= (sig["wildcards"] / max(sig["length"], 1)) * 20.0
    score -= sig["length"] * 0.15
    return round(score, 3)


def build_struct_offset_signatures(image, name, old_disp, safe_disps, trusted_globals,
                                    keep=5, max_sites=80, verbose=True):
    md = make_disassembler()
    text_sections = image.exec_sections()
    sites = find_disp32_sites(image, md, text_sections, old_disp, max_sites=max_sites)

    anchored = []
    reasons = []
    for site in sites:
        sec = image.section_for_va(site.va)
        ok, reason = is_anchored(md, sec, site, safe_disps, trusted_globals)
        if ok:
            anchored.append(site)
            reasons.append(reason)

    if verbose:
        print(f"  {name}: 0x{old_disp:X} -> {len(sites)} site(s), {len(anchored)} anchored")

    sigs = []
    for site in anchored:
        sec = image.section_for_va(site.va)
        sig = build_signature_for_site(image, md, sec, site, text_sections)
        if sig:
            sig["score"] = score_signature(sig)
            sigs.append(sig)

    sigs.sort(key=lambda s: s["score"], reverse=True)
    sigs = sigs[:keep]
    for i, s in enumerate(sigs):
        s["id"] = f"{name}#{i}"

    if verbose:
        if sigs:
            print(f"  {name}: kept {len(sigs)} signature(s)")
        elif not sites:
            print(f"  {name}: no disp32 references found "
                  f"(likely disp8-encoded, or the known value is stale) -- not derivable yet")
        elif not anchored:
            print(f"  {name}: {len(sites)} reference(s) found but NONE anchored to a "
                  f"known spawn pointer -- refusing to guess")
        else:
            print(f"  {name}: WARNING all anchored sites were ambiguous or too short")

    return sigs
