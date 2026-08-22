"""Turn reference sites into byte signatures that survive a patch.

A signature is the instruction bytes around a reference site, with every
byte that encodes an *address* replaced by a wildcard. The surviving
concrete bytes are opcodes, register encodings and small constants -- the
parts that come straight from the source code and therefore do not move
when the compiler relays out the binary.

We wildcard:
  * the RIP-relative disp32 of any instruction in the window
  * call/jmp/jcc relative displacements
  * any immediate whose value falls inside the image (i.e. is an address)

We deliberately do NOT wildcard non-RIP displacements such as the 0x564 in
`mov eax, [rcx+0x564]`. Those are structure member offsets: they are stable,
they are meaningful, and keeping them concrete makes signatures much more
selective.

A signature is only kept if it matches EXACTLY ONCE in the source binary.
Zero matches means we built it wrong; two or more means it is ambiguous and
would eventually resolve to the wrong global. Skipping this check is the
main reason hobby offset tools fail mysteriously.
"""

from capstone import CS_GRP_JUMP, CS_GRP_CALL

from .refs import make_disassembler, rip_target, find_refs
from .scan import format_pattern, compile_pattern, find_all

MAX_WINDOW_INSNS = 12
MIN_SIG_BYTES = 8
MIN_ANCHOR_BYTES = 4


def _wildcard_ranges(image, insn):
    """Byte ranges within `insn` that encode an address and must be wildcarded."""
    ranges = []
    enc = insn.encoding

    if enc.disp_size == 4 and rip_target(insn) is not None:
        ranges.append((enc.disp_offset, 4))

    if enc.imm_size:
        is_branch = insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)
        imm_val = None
        for op in insn.operands:
            if op.type == 2:  # X86_OP_IMM
                imm_val = op.imm
        looks_like_address = imm_val is not None and image.in_image(imm_val)
        if is_branch or looks_like_address:
            ranges.append((enc.imm_offset, enc.imm_size))

    return ranges


def _window(image, md, site, max_insns=MAX_WINDOW_INSNS):
    """Disassemble forward from a site, yielding cumulative (bytes, mask, notes)."""
    sec = image.section_for_va(site.va)
    if sec is None:
        return
    start = site.va - sec.va
    chunk = sec.data[start:start + max_insns * 16 + 16]

    pat = bytearray()
    mask = []
    string_anchor = None
    first_len = None

    for idx, insn in enumerate(md.disasm(chunk, site.va, count=max_insns)):
        if idx == 0:
            first_len = insn.size
        base = len(pat)
        pat.extend(insn.bytes)
        mask.extend("x" * insn.size)
        for off, size in _wildcard_ranges(image, insn):
            for k in range(size):
                if 0 <= base + off + k < len(mask):
                    mask[base + off + k] = "?"

        if string_anchor is None:
            t = rip_target(insn)
            if t is not None:
                s = image.cstring_at(t)
                if s:
                    string_anchor = s

        yield bytes(pat), "".join(mask), first_len, string_anchor


def build_signature_for_site(image, md, site, text_sections):
    """Shortest unique signature anchored at `site`, or None."""
    for pat, mask, first_len, string_anchor in _window(image, md, site):
        if len(pat) < MIN_SIG_BYTES:
            continue
        pattern_text = format_pattern(pat, mask)
        compiled = compile_pattern(pattern_text)
        if compiled.anchor_len < MIN_ANCHOR_BYTES:
            continue

        total = 0
        for sec in text_sections:
            total += len(find_all(sec.data, compiled, limit=2))
            if total > 1:
                break
        if total != 1:
            continue

        return {
            "pattern": pattern_text,
            "extract": "rip_target",
            "disp_off": site.disp_off,
            "insn_len": first_len,
            "site_va": f"0x{site.va:X}",
            "insn": site.text,
            "string_anchor": string_anchor,
            "length": len(pat),
            "wildcards": mask.count("?"),
            "anchor_len": compiled.anchor_len,
        }
    return None


def score_signature(sig):
    """Higher is better. Ordering rationale:

    - a nearby string literal is the most stable landmark in a binary
    - a long concrete run makes scanning fast and matches selective
    - fewer wildcards means less of the pattern is address-dependent
    - shorter windows span less code and so survive edits better
    """
    score = 0.0
    if sig.get("string_anchor"):
        score += 25.0
    score += min(sig["anchor_len"], 16) * 2.0
    score -= (sig["wildcards"] / max(sig["length"], 1)) * 20.0
    score -= sig["length"] * 0.15
    return round(score, 3)


def build_offset_signatures(image, name, target, keep=5, max_sites=40, verbose=True):
    md = make_disassembler()
    text_sections = image.exec_sections()
    sites = find_refs(image, target, md=md, sections=text_sections, max_sites=max_sites)

    if verbose:
        print(f"  {name}: 0x{target:X} -> {len(sites)} reference site(s)")

    sigs = []
    for site in sites:
        sig = build_signature_for_site(image, md, site, text_sections)
        if sig:
            sig["score"] = score_signature(sig)
            sigs.append(sig)

    sigs.sort(key=lambda s: s["score"], reverse=True)
    sigs = sigs[:keep]
    for i, s in enumerate(sigs):
        s["id"] = f"{name}#{i}"

    if verbose:
        print(f"  {name}: kept {len(sigs)} unique signature(s)")
        if not sigs and sites:
            print(f"  {name}: WARNING all sites were ambiguous or too short")
        if not sites:
            print(f"  {name}: WARNING no references found -- is the address correct?")

    return sigs
