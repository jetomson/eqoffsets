"""End-to-end test on a synthetic x64 image.

We build a fake .text containing several RIP-relative references to a global,
build signatures against it, then build a *second* image that simulates a
patch: the global moves to a new address AND the code shifts position, so
every disp32 in the file is different. If the signatures still recover the
correct new address, the core logic is sound.

This is the regression oracle. Run it before you trust any real output.
"""

import configparser
import struct
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eqoffsets.pe import Section
from eqoffsets.refs import find_refs
from eqoffsets.sigbuild import build_offset_signatures
from eqoffsets.structsig import build_struct_offset_signatures, signatures_from_sites
from eqoffsets.resolve import resolve_offset, resolve_all
from eqoffsets.scan import compile_pattern, find_all, parse_pattern, format_pattern
from eqoffsets.buildinfo import extract_build_string
from eqoffsets.codemap import CodeMap, function_ranges
from eqoffsets.anchor import StructKind, find_anchored_sites
from eqoffsets.cli import (_check_pair, _norm_value, _ini_up_to_date, _latest_pair,
                           _parse_disp, _format_disp, _evaluate_struct_fields,
                           _remembered_path)
from eqoffsets import config as pathconfig
from eqoffsets.review import gather_candidates, build_field_report, build_markdown


class FakeImage:
    """Duck-typed stand-in for PEImage.

    `functions` optionally synthesizes a .pdata RUNTIME_FUNCTION table, which
    is how codemap.py recovers instruction alignment on a real binary. Without
    it the image exercises the no-.pdata fallback path instead.
    """

    def __init__(self, text_va, text_bytes, data_va, data_bytes, image_base=0x140000000,
                 functions=None):
        self.image_base = image_base
        self.size_of_image = 0x2000000
        self.machine = 0x8664
        self.sections = [
            Section(".text", text_va - image_base, text_va, len(text_bytes), text_bytes, True),
            Section(".data", data_va - image_base, data_va, len(data_bytes), data_bytes, False),
        ]
        if functions:
            pdata = b"".join(
                struct.pack("<III", start - image_base, end - image_base, 0)
                for start, end in functions
            )
            pdata_va = 0x140900000
            self.sections.append(
                Section(".pdata", pdata_va - image_base, pdata_va, len(pdata), pdata, False))

    is_x64 = True

    def exec_sections(self):
        return [s for s in self.sections if s.executable]

    def section_by_name(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_for_va(self, va):
        for s in self.sections:
            if s.contains(va):
                return s
        return None

    def in_image(self, va):
        return self.image_base <= va < self.image_base + self.size_of_image

    def read_va(self, va, length):
        s = self.section_for_va(va)
        return s.data[va - s.va: va - s.va + length] if s else None

    def cstring_at(self, va, maxlen=96):
        return None


# --- tiny x64 encoders -------------------------------------------------

def mov_rax_rip(disp):
    return b"\x48\x8b\x05" + struct.pack("<i", disp)      # mov rax, [rip+d]   len 7


def lea_rcx_rip(disp):
    return b"\x48\x8d\x0d" + struct.pack("<i", disp)      # lea rcx, [rip+d]   len 7


def mov_eax_rip(disp):
    return b"\x8b\x05" + struct.pack("<i", disp)          # mov eax, [rip+d]   len 6


def mov_rax_imm32(v):
    return b"\x48\xc7\xc0" + struct.pack("<I", v)         # mov rax, imm32     len 7


def mov_ecx_mem_disp(reg_disp):
    return b"\x8b\x89" + struct.pack("<i", reg_disp)      # mov ecx, [rcx+d]   len 6


def mov_rcx_rip(disp):
    return b"\x48\x8b\x0d" + struct.pack("<i", disp)      # mov rcx, [rip+d]   len 7


def mov_rax_rax_disp8(d8):
    return b"\x48\x8b\x40" + bytes([d8])                  # mov rax, [rax+d8]  len 4


def movzx_ecx_rax_disp8(d8):
    return b"\x0f\xb6\x48" + bytes([d8])                  # movzx ecx,byte[rax+d8] len 4


def movzx_eax_rcx_disp32(d):
    return b"\x0f\xb6\x81" + struct.pack("<i", d)         # movzx eax,byte[rcx+d]  len 7


def mov_eax_rbx_disp32(d):
    return b"\x8b\x83" + struct.pack("<i", d)             # mov eax, [rbx+d]   len 6


def call_mem_rax_disp32(d):
    return b"\xff\x90" + struct.pack("<i", d)             # call qword [rax+d] len 6


def call_rel32(from_va, to_va):
    return b"\xe8" + struct.pack("<i", to_va - (from_va + 5))   # call rel32   len 5


def jmp_rel32(from_va, to_va):
    return b"\xe9" + struct.pack("<i", to_va - (from_va + 5))   # jmp rel32    len 5


def unique_trailer(tag):
    """Address-free bytes that make a surrounding signature unique."""
    return mov_rax_imm32(tag) + b"\xc3" + b"\x90" * 3


ENCODERS = [mov_rax_rip, lea_rcx_rip, mov_eax_rip]
ENC_LEN = {mov_rax_rip: 7, lea_rcx_rip: 7, mov_eax_rip: 6}


def build_image(text_va, target_va, lead_pad, n_sites=4):
    """Synthesize an image with n_sites references to target_va."""
    text = bytearray(b"\x90" * lead_pad)
    for i in range(n_sites):
        enc = ENCODERS[i % len(ENCODERS)]
        site_off = len(text)
        site_va = text_va + site_off
        disp = target_va - (site_va + ENC_LEN[enc])
        text += enc(disp)
        # Unique, address-free trailing bytes so each signature is distinct.
        text += mov_rax_imm32(0x1000 + i)
        text += mov_ecx_mem_disp(0x500 + i * 4)
        text += b"\xc3" + b"\x90" * (5 + i)

    data = bytes(0x40000)
    data_va = 0x140800000
    # Ensure the target actually lands inside .data for validation purposes.
    assert data_va <= target_va < data_va + len(data), "target must be in .data"
    return FakeImage(text_va, bytes(text), data_va, data)


# --- tests -------------------------------------------------------------

def test_scanner_wildcards():
    data = b"\x00\x11\x48\x8b\x05\xAA\xBB\xCC\xDD\x90\xc3"
    c = compile_pattern("48 8B 05 ?? ?? ?? ?? 90")
    hits = find_all(data, c)
    assert hits == [2], hits

    # round trip
    pat, mask = parse_pattern("48 ?? C0")
    assert format_pattern(pat, mask) == "48 ?? C0"
    print("  scanner wildcards ok")


def test_scanner_uniqueness_counting():
    data = b"\xAA\xBB\xCC" * 3
    c = compile_pattern("AA BB CC")
    assert len(find_all(data, c)) == 3
    assert len(find_all(data, c, limit=2)) == 2
    print("  scanner uniqueness counting ok")


def test_find_refs():
    target = 0x140801234
    img = build_image(0x140001000, target, lead_pad=0x10)
    sites = find_refs(img, target)
    assert len(sites) == 4, f"expected 4 sites, got {len(sites)}"
    for s in sites:
        assert s.target == target
    print(f"  find_refs found {len(sites)} sites ok")


def test_rip_math_off_by_one_guard():
    """A reference must resolve exactly, not near-miss."""
    target = 0x140801234
    img = build_image(0x140001000, target, lead_pad=0x10)
    assert find_refs(img, target + 1) == []
    assert find_refs(img, target - 1) == []
    print("  rip math rejects near-miss targets ok")


def test_end_to_end_across_a_patch():
    old_target = 0x140801234
    new_target = 0x140805AB0          # global moved
    old = build_image(0x140001000, old_target, lead_pad=0x10)
    new = build_image(0x140001000, new_target, lead_pad=0x37)   # code also shifted

    sigs = build_offset_signatures(old, "CharInfo", old_target, verbose=False)
    assert sigs, "no signatures built"

    # Signatures must not contain the old address anywhere.
    for s in sigs:
        assert "34 12 80 40" not in s["pattern"], "old address leaked into pattern"

    res = resolve_offset(new, "CharInfo", sigs)
    assert res.ok, f"failed to resolve: {res.failures}"
    assert res.value == new_target, f"got 0x{res.value:X}, want 0x{new_target:X}"
    assert res.unanimous, f"signatures disagreed: {res.votes}"
    print(f"  end-to-end: {len(sigs)} sigs -> 0x{res.value:X} unanimous ok")


def test_detects_broken_signature():
    """If a pattern no longer matches, resolve reports it instead of guessing."""
    old_target = 0x140801234
    old = build_image(0x140001000, old_target, lead_pad=0x10)
    sigs = build_offset_signatures(old, "CharInfo", old_target, verbose=False)

    broken = [dict(sigs[0])]
    broken[0]["pattern"] = "DE AD BE EF DE AD BE EF"
    res = resolve_offset(old, "CharInfo", broken)
    assert not res.ok
    assert "no match" in list(res.failures.values())[0]
    print("  broken signature detected ok")


def test_crosscheck_pair_all_pass():
    """_check_pair builds sigs from patch1 and resolves all correctly against patch2."""
    old_target = 0x140801234
    new_target = 0x140805AB0
    old = build_image(0x140001000, old_target, lead_pad=0x10)
    new = build_image(0x140001000, new_target, lead_pad=0x37)

    old_known = {"memory_offsets": {"TestAddr": f"0x{old_target:X}"}}
    new_known = {"memory_offsets": {"TestAddr": f"0x{new_target:X}"}}

    result = _check_pair(old, old_known, new, new_known)

    entry = result["TestAddr"]
    assert entry["passed"], f"expected pass: {entry}"
    assert entry["got"] == new_target
    assert entry["unanimous"]
    assert entry["sig_results"], "no sig_results recorded"

    for sid, sr in entry["sig_results"].items():
        assert sr["matched"], f"{sid} did not match in new binary"
        assert sr["correct"], f"{sid} voted wrong value: {sr}"
        assert sr["failure"] is None

    n = len(entry["sig_results"])
    print(f"  crosscheck pair: all {n} sigs correct across the patch ok")


def test_crosscheck_per_sig_failure_tracked():
    """A sig that breaks at a patch boundary is recorded individually; others still resolve."""
    old_target = 0x140801234
    new_target = 0x140805AB0
    old = build_image(0x140001000, old_target, lead_pad=0x10)
    new = build_image(0x140001000, new_target, lead_pad=0x37)

    sigs = build_offset_signatures(old, "TestAddr", old_target, verbose=False)
    assert len(sigs) >= 2, "need at least 2 sigs for this test"

    # Simulate a sig that breaks at a patch boundary by corrupting its pattern.
    mixed = [dict(sigs[0])] + [dict(s) for s in sigs[1:]]
    mixed[0]["pattern"] = "DE AD BE EF DE AD BE EF"

    res = resolve_offset(new, "TestAddr", mixed)

    # Majority of surviving sigs must still resolve the correct value.
    assert res.ok and res.value == new_target, \
        f"remaining sigs should carry the vote: failures={res.failures}"

    # Broken sig must appear in failures, not in votes.
    broken_id = mixed[0]["id"]
    assert broken_id in res.failures, f"broken sig {broken_id} not in failures"
    assert broken_id not in res.votes

    # All intact sigs must be in votes with the correct value.
    for s in mixed[1:]:
        sid = s["id"]
        assert sid in res.votes, f"{sid} missing from votes"
        assert res.votes[sid] == new_target, f"{sid} voted wrong: 0x{res.votes[sid]:X}"

    print(f"  crosscheck per-sig tracking: {len(res.votes)} correct, "
          f"{len(res.failures)} failed, disagreement surfaced ok")


def test_struct_offset_anchored_site_survives_patch():
    """A struct-member displacement reached via a known-safe dereference
    (the PrevOffset=0x10 linked-list pointer) should be derivable across a
    simulated patch, the same way sigbuild derives RIP-relative globals."""
    old_disp = 0x300
    new_disp = 0x150
    trailer = b"\x48\xC7\xC0" + struct.pack("<I", 0x9999) + b"\xC3" + b"\x90" * 4

    def make(disp, lead_pad):
        text = bytearray(b"\x90" * lead_pad)
        text += bytes.fromhex("48 8B 40 10")                        # mov rax, [rax+0x10]
        text += bytes.fromhex("0F B6 88") + struct.pack("<i", disp)  # movzx ecx, byte [rax+disp]
        text += trailer
        return FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    old = make(old_disp, lead_pad=0x10)
    new = make(new_disp, lead_pad=0x37)   # code also shifts, like a real patch

    sigs = build_struct_offset_signatures(
        old, "HideOffset", old_disp, safe_disps={0x10}, trusted_globals=set(), verbose=False)
    assert sigs, "no anchored signatures built"

    res = resolve_all(new, {"offsets": {
        "HideOffset": {"known_value": f"0x{old_disp:X}", "signatures": sigs}}})
    r = res["HideOffset"]
    assert r.ok, f"failed to resolve: {r.failures}"
    assert r.value == new_disp, f"got 0x{r.value:X}, want 0x{new_disp:X}"
    assert r.unanimous, f"signatures disagreed: {r.votes}"
    print(f"  struct offset anchored derivation: 0x{old_disp:X} -> 0x{new_disp:X} ok")


def test_struct_offset_rejects_unanchored_decoy():
    """Regression test for the real HideOffset mistake: a byte-identical
    match on an unrelated, unmodified field must not get to vote just
    because it happens to reference the same old displacement value. Only
    a site anchored via a known-safe dereference should be trusted."""
    old_disp = 0x4D0            # mirrors the real HideOffset value
    new_disp_true = 0x304       # mirrors the real corrected value
    trailer = b"\x48\xC7\xC0" + struct.pack("<I", 0x8888) + b"\xC3" + b"\x90" * 4

    def make(true_disp, lead_pad):
        text = bytearray(b"\x90" * lead_pad)
        # Decoy: an unrelated field access on a register never derived via a
        # safe offset. It does NOT move across the patch -- exactly the
        # shape of the real false positive (unrelated code that just didn't
        # change), which is what makes "unchanged" look like false evidence.
        text += bytes.fromhex("48 8B 93") + struct.pack("<i", old_disp)  # mov rdx, [rbx+old_disp]
        text += trailer
        text += b"\x90" * 5
        # The real, anchored site: reached via the PrevOffset=0x10 dereference.
        text += bytes.fromhex("48 8B 40 10")                              # mov rax, [rax+0x10]
        text += bytes.fromhex("0F B6 88") + struct.pack("<i", true_disp)  # movzx ecx, byte [rax+disp]
        text += trailer
        return FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    old = make(old_disp, lead_pad=0x10)
    new = make(new_disp_true, lead_pad=0x37)

    sigs = build_struct_offset_signatures(
        old, "HideOffset", old_disp, safe_disps={0x10}, trusted_globals=set(), verbose=False)
    assert sigs, "no anchored signatures built"

    res = resolve_all(new, {"offsets": {
        "HideOffset": {"known_value": f"0x{old_disp:X}", "signatures": sigs}}})
    r = res["HideOffset"]
    assert r.ok, f"failed to resolve: {r.failures}"
    assert r.value == new_disp_true, (
        f"got 0x{r.value:X} -- if this is 0x{old_disp:X}, the unanchored decoy "
        f"was not filtered out and voted for its own unrelated field")
    assert r.unanimous, f"decoy should have been excluded entirely, got votes {r.votes}"
    print(f"  struct offset anchoring rejects unanchored decoy "
          f"(decoy would vote 0x{old_disp:X}, correctly got 0x{new_disp_true:X}) ok")


def test_struct_offset_disp8_field():
    """disp8-encoded fields (anything under 0x80 -- NextOffset, X/Y/ZOffset,
    LastnameOffset) used to be out of scope entirely: the old site search
    scanned for the 4-byte little-endian value, which cannot see a one-byte
    displacement. Anchoring works off decoded instructions instead, so the
    encoding width no longer decides whether a field is derivable."""
    old_d8, new_d8 = 0x48, 0x50

    def make(d8, lead_pad, tag):
        text = bytearray(b"\x90" * lead_pad)
        text += mov_rax_rax_disp8(0x10)      # walk PrevOffset -> anchors rax
        text += movzx_ecx_rax_disp8(d8)      # the field itself, disp8-encoded
        text += unique_trailer(tag)
        return FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    old = make(old_d8, lead_pad=0x10, tag=0x4141)
    new = make(new_d8, lead_pad=0x37, tag=0x4141)

    sigs = build_struct_offset_signatures(
        old, "LastnameOffset", old_d8, safe_disps={0x10}, trusted_globals=set(),
        verbose=False)
    assert sigs, "no signature built for a disp8 field"
    assert all(s["disp_size"] == 1 for s in sigs), \
        f"expected disp8 extraction, got {[s['disp_size'] for s in sigs]}"

    r = resolve_all(new, {"offsets": {"LastnameOffset": {"signatures": sigs}}})["LastnameOffset"]
    assert r.ok and r.value == new_d8, f"got {r.value!r}, want 0x{new_d8:X}: {r.failures}"
    assert r.consistent, f"signatures disagreed: {r.votes}"
    print(f"  disp8 struct field derived: 0x{old_d8:X} -> 0x{new_d8:X} ok")


def test_pdata_function_ranges():
    """.pdata is the compiler's own function table; codemap uses it instead of
    guessing boundaries from 0xCC padding. Without it we fall back to
    whole-section spans, which is only safe on synthetic images."""
    text_va = 0x140001000
    text = bytes(0x100)
    funcs = [(text_va, text_va + 0x20), (text_va + 0x20, text_va + 0x40)]
    img = FakeImage(text_va, text, 0x140800000, bytes(0x1000), functions=funcs)

    assert function_ranges(img) == funcs, function_ranges(img)
    cm = CodeMap(img)
    assert cm.from_pdata, "should have used .pdata"
    assert cm.functions == funcs

    # A .pdata record pointing outside any executable section is not a
    # function we can decode; it must be dropped, not clamped into nonsense.
    bogus = FakeImage(text_va, text, 0x140800000, bytes(0x1000),
                      functions=[(text_va, text_va + 0x20), (0x140800000, 0x140800010)])
    assert function_ranges(bogus) == [(text_va, text_va + 0x20)], function_ranges(bogus)

    no_pdata = FakeImage(text_va, text, 0x140800000, bytes(0x1000))
    assert function_ranges(no_pdata) == []
    assert not CodeMap(no_pdata).from_pdata
    print("  .pdata function ranges parsed, out-of-section records dropped ok")


def test_anchor_follows_this_pointer_into_callee():
    """The fields worth having (OwnerID, Hide, the WorldInfo bytes) are read
    inside accessor methods, not at the site that loads the global. Trust has
    to survive a call: a direct call made with a trusted register in rcx means
    the callee's `this` is that struct."""
    text_va = 0x140001000
    global_va = 0x140800100
    field = 0x300

    caller_off, callee_off = 0x00, 0x20
    caller_va, callee_va = text_va + caller_off, text_va + callee_off

    text = bytearray(b"\xcc" * 0x40)
    mov_at = caller_va
    text[caller_off:caller_off + 7] = mov_rcx_rip(global_va - (mov_at + 7))
    call_at = caller_va + 7
    text[caller_off + 7:caller_off + 12] = call_rel32(call_at, callee_va)
    text[caller_off + 12] = 0xC3

    body = movzx_eax_rcx_disp32(field) + unique_trailer(0x5151)
    text[callee_off:callee_off + len(body)] = body

    data = bytearray(0x40000)
    img = FakeImage(text_va, bytes(text), 0x140800000, bytes(data),
                    functions=[(caller_va, caller_va + 0x20), (callee_va, callee_va + 0x20)])

    kind = StructKind(name="spawn", root_globals={global_va}, link_disps=set(),
                      field_disps={field})
    sites = find_anchored_sites(img, [kind], want={"spawn": {field}})
    anchored = sites.get("spawn", {}).get(field, [])
    assert anchored, "the callee's field access was never anchored"
    assert any(s.anchor == "this" for s in anchored), \
        f"expected a 'this' anchor, got {[s.anchor for s in anchored]}"

    # Same code with the call removed: nothing reaches the callee, so the
    # access must stay unanchored rather than be trusted on its own.
    severed = bytearray(text)
    severed[caller_off + 7:caller_off + 12] = b"\x90" * 5
    img2 = FakeImage(text_va, bytes(severed), 0x140800000, bytes(data),
                     functions=[(caller_va, caller_va + 0x20), (callee_va, callee_va + 0x20)])
    assert not find_anchored_sites(img2, [kind], want={"spawn": {field}}).get("spawn"), \
        "callee field access was trusted without any caller establishing `this`"
    print("  anchoring follows `this` through a direct call ok")


def test_anchor_follows_this_through_tail_call_jmp():
    """MSVC compiles a trivial one-line forwarder as a tail call: `jmp` straight
    to the callee's entry point instead of `call`+`ret`. That still passes
    `this` in rcx, so it has to propagate trust the same way a direct call
    does -- this is what let LevelOffset pick up an extra anchored site
    across the real 08/19->09/11/2026 boundary. An ordinary `jmp` used for
    in-function control flow must NOT trigger this -- it targets some address
    inside the current function, never another function's entry point, which
    is exactly the distinction `codemap.function_starts` exists to draw."""
    text_va = 0x140001000
    global_va = 0x140800100
    field = 0x300

    caller_off, callee_off = 0x00, 0x20
    caller_va, callee_va = text_va + caller_off, text_va + callee_off

    text = bytearray(b"\xcc" * 0x40)
    text[caller_off:caller_off + 7] = mov_rcx_rip(global_va - (caller_va + 7))
    text[caller_off + 7:caller_off + 12] = jmp_rel32(caller_va + 7, callee_va)

    body = movzx_eax_rcx_disp32(field) + unique_trailer(0x6262)
    text[callee_off:callee_off + len(body)] = body

    data = bytearray(0x40000)
    img = FakeImage(text_va, bytes(text), 0x140800000, bytes(data),
                    functions=[(caller_va, caller_va + 0x20), (callee_va, callee_va + 0x20)])

    kind = StructKind(name="spawn", root_globals={global_va}, link_disps=set(),
                      field_disps={field})
    anchored = find_anchored_sites(img, [kind], want={"spawn": {field}})
    sites = anchored.get("spawn", {}).get(field, [])
    assert sites, "tail-call jmp did not propagate `this` into the callee"
    assert all(s.anchor == "this" for s in sites), \
        f"expected a 'this' anchor via the tail call, got {[s.anchor for s in sites]}"
    print("  anchoring follows `this` through a tail-call jmp ok")


def test_disasm_window_and_match_va():
    """The UNCONFIRMED-field diagnostic (cli.py's _dissent_windows) depends on
    two things: resolve.py recording exactly where each signature matched,
    and CodeMap being able to hand back readable disassembly there. Both are
    what let a person judge a disagreeing vote by eye instead of waiting on
    someone else's published list.

    Uses mov_eax_rip specifically (a bare 6-byte `8B 05 disp32`, no REX
    prefix) rather than build_image's default encoder mix: a REX.W-prefixed
    7-byte RIP form's *target arithmetic* is byte-identical to the same
    bytes read one byte later as a REX-less 6-byte form (dropping the prefix
    shortens insn_len by exactly the byte it removes from insn_va), so
    find_refs's backward search can legitimately land a site one byte off
    from where linear disassembly from a function's start would put it.
    That is a real, harmless ambiguity in which alias gets treated as "the"
    instruction -- both compute the correct target -- but it means such a
    site is the wrong fixture for a test asserting alignment against a
    from-the-start linear decode. The 6-byte form has no such alias.
    """
    text_va = 0x140001000
    target = 0x140801234
    text = bytearray(b"\x90" * 0x10)
    text += mov_eax_rip(target - (text_va + 0x10 + 6))
    text += unique_trailer(0x9191)
    old = FakeImage(text_va, bytes(text), 0x140800000, bytes(0x1000))

    sigs = build_offset_signatures(old, "CharInfo", target, verbose=False)
    assert sigs, "no signature built"
    res = resolve_offset(old, "CharInfo", sigs)
    assert res.ok
    for sid in res.votes:
        assert sid in res.match_va, f"{sid} matched but recorded no site address"

    cm = CodeMap(old)
    some_va = next(iter(res.match_va.values()))
    assert some_va == text_va + 0x10, \
        f"expected the site at 0x{text_va + 0x10:X}, got 0x{some_va:X}"
    window = cm.disasm_window(some_va)
    assert window, "disasm_window found nothing at a real match site"
    assert any(insn.address == some_va for insn in window), \
        "disasm_window's result doesn't include the requested address itself"

    # An address with no .pdata-backed function around it (this FakeImage has
    # none) must come back empty, not raise or fabricate a window.
    assert cm.disasm_window(0x140999999) == []
    print("  disasm_window/match_va wiring for the UNCONFIRMED diagnostic ok")


def test_vtable_call_is_not_a_struct_field():
    """`call qword ptr [rax+0x90]` indexes a vtable, not a data member. The
    only GroundItem.YOffset signature to vote wrong across the real
    07/17->08/19 boundary was built on exactly this instruction shape."""
    disp = 0x90

    def make(kind_bytes):
        text = bytearray(b"\x90" * 0x10)
        text += mov_rax_rax_disp8(0x10)     # anchors rax
        text += kind_bytes
        text += unique_trailer(0x6161)
        return FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    kind = StructKind(name="struct", root_globals=set(), link_disps={0x10},
                      field_disps={disp})

    vtable = make(call_mem_rax_disp32(disp))
    assert not find_anchored_sites(vtable, [kind], want={"struct": {disp}}).get("struct"), \
        "a virtual dispatch was mistaken for a struct field access"

    # The filter must be about the instruction, not the displacement: a plain
    # load at the same offset off the same register is still a real site.
    load = make(b"\x8b\x80" + struct.pack("<i", disp))      # mov eax, [rax+disp]
    assert load and find_anchored_sites(load, [kind], want={"struct": {disp}}).get("struct"), \
        "a genuine field load at the same offset was filtered out too"
    print("  vtable call excluded, plain load at same offset kept ok")


def test_shape_anchoring_is_off_by_default():
    """Shape anchoring -- trusting a register because the function uses it
    with several known field offsets -- measured 82% cross-patch survival
    against 95-100% for dataflow anchors, and fails by claiming moved fields
    stayed put. It must stay opt-in."""
    fields = [0x100, 0x200, 0x300, 0x400]
    target = 0x500

    text = bytearray(b"\x90" * 0x10)
    for d in fields:
        text += mov_eax_rbx_disp32(d)      # rbx is never traced to anything
    text += mov_eax_rbx_disp32(target)
    text += unique_trailer(0x7171)
    img = FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    kind = StructKind(name="spawn", root_globals=set(), link_disps=set(),
                      field_disps=set(fields) | {target})
    want = {"spawn": {target}}

    assert not find_anchored_sites(img, [kind], want=want).get("spawn"), \
        "shape anchoring fired without being asked for"
    opted_in = find_anchored_sites(img, [kind], want=want, enable_shape=True)
    assert opted_in.get("spawn", {}).get(target), "enable_shape=True found nothing"
    assert all(s.anchor == "shape" for s in opted_in["spawn"][target])
    print("  shape anchoring off by default, available opt-in ok")


def test_crosscheck_covers_struct_fields():
    """crosscheck is the only measurement that says whether any of this
    survives a patch, so it has to score struct fields too -- not just the
    RIP-relative globals."""
    old_global, new_global = 0x140801234, 0x140805AB0
    old_field, new_field = 0x300, 0x210

    text_va = 0x140001000

    def make(global_va, field, lead_pad):
        text = bytearray(b"\x90" * lead_pad)
        # Block 1: a reference to the global with no struct access after it, so
        # the global's own signature does not span the field being moved.
        site = text_va + len(text)
        text += mov_rcx_rip(global_va - (site + 7))
        text += unique_trailer(0x8181)
        # Block 2: the same global, then the field read it anchors.
        site = text_va + len(text)
        text += mov_rcx_rip(global_va - (site + 7))
        text += movzx_eax_rcx_disp32(field)
        text += unique_trailer(0x8282)
        return FakeImage(text_va, bytes(text), 0x140800000, bytes(0x40000))

    old = make(old_global, old_field, lead_pad=0x10)
    new = make(new_global, new_field, lead_pad=0x37)

    old_known = {"memory_offsets": {"CharInfo": f"0x{old_global:X}"},
                 "static_sections": {"SpawnInfo Offsets": {"LevelOffset": f"0x{old_field:x}"}}}
    new_known = {"memory_offsets": {"CharInfo": f"0x{new_global:X}"},
                 "static_sections": {"SpawnInfo Offsets": {"LevelOffset": f"0x{new_field:x}"}}}

    result = _check_pair(old, old_known, new, new_known)

    assert "CharInfo" in result and result["CharInfo"]["passed"], result.get("CharInfo")
    key = "SpawnInfo.LevelOffset"
    assert key in result, f"struct fields missing from crosscheck: {sorted(result)}"
    assert result[key]["passed"], result[key]
    assert result[key]["got"] == new_field
    assert result[key]["sig_results"], "no per-signature records for the struct field"
    for sid, sr in result[key]["sig_results"].items():
        assert sr["anchor"], f"{sid} recorded no anchor kind to calibrate against"
    print(f"  crosscheck scores struct fields: {key} 0x{old_field:X} -> 0x{new_field:X} ok")


def test_struct_offset_radix_round_trip():
    """[WorldInfo Offsets] is written in decimal and everything else in hex.
    Reading '10' as hex turns a correct derivation into a reported failure --
    which is exactly what selftest did before this was threaded through."""
    assert _parse_disp("10", 10) == 10
    assert _parse_disp("10", 16) == 16
    assert _parse_disp("0x10", 10) == 16        # explicit prefix always wins
    assert _format_disp(12, 10) == "12"
    assert _format_disp(12, 16) == "0xc"
    for radix in (10, 16):
        for value in (0, 8, 12, 0x210, 0x10f8):
            assert _parse_disp(_format_disp(value, radix), radix) == value
    print("  struct offset radix round trip ok")


def test_review_report_and_markdown():
    """The manual-review doc (review.py) is what lets someone resolve an
    UNCONFIRMED field themselves instead of waiting for a published list --
    this drives the real build->resolve->report pipeline end to end with a
    fixture engineered to genuinely disagree, the same way HideOffset did
    for real across the 08/19->09/11/2026 boundary."""
    old_disp = 0x300
    trailer_a = unique_trailer(0xAAAA)
    trailer_b = unique_trailer(0xBBBB)

    def make(disp_a, disp_b, lead_pad):
        text = bytearray(b"\x90" * lead_pad)
        text += bytes.fromhex("48 8B 40 10")                          # mov rax, [rax+0x10]
        text += bytes.fromhex("0F B6 88") + struct.pack("<i", disp_a)  # movzx ecx, byte [rax+d]
        text += trailer_a
        text += bytes.fromhex("48 8B 40 10")
        text += bytes.fromhex("0F B6 90") + struct.pack("<i", disp_b)  # movzx edx, byte [rax+d]
        text += trailer_b
        return FakeImage(0x140001000, bytes(text), 0x140800000, bytes(0x1000))

    old = make(old_disp, old_disp, lead_pad=0x10)
    new = make(0x150, 0x160, lead_pad=0x37)   # same old site, two different new values -> disagreement

    sigs = build_struct_offset_signatures(
        old, "SomeField", old_disp, safe_disps={0x10}, trusted_globals=set(), verbose=False)
    assert len(sigs) >= 2, "need at least 2 disagreeing signatures for this fixture"

    res = resolve_all(new, {"offsets": {"SomeField": {"signatures": sigs}}})["SomeField"]
    assert res.ok and not res.consistent, "fixture should produce genuine disagreement"

    rep = build_field_report(
        "Test.SomeField", res, radix=16, signatures=sigs, format_disp=_format_disp,
        codemap=CodeMap(new), old_codemap=CodeMap(old),
        known_val="0x300", status="unconfirmed", why=res.summary())

    assert len(rep["candidates"]) >= 2
    assert {c["value"] for c in rep["candidates"]} == {0x150, 0x160}
    for c in rep["candidates"]:
        assert c["new_window"], f"missing new-binary window for candidate 0x{c['value']:x}"
        assert c["old_window"], f"missing old-binary window for candidate 0x{c['value']:x}"

    md = build_markdown([rep], meta={"binary": "fake.exe"})
    assert "Test.SomeField" in md
    assert "0x150" in md and "0x160" in md
    assert "old binary, as originally derived" in md
    assert "this binary" in md
    assert "How to resolve this by hand" in md

    assert build_field_report(
        "X", None, 16, [], _format_disp, None, None, "0x1", "unconfirmed", "no signatures"
    )["candidates"] == [], "no Resolution/votes should degrade to zero candidates, not raise"
    assert "Nothing needs manual review" in build_markdown([])
    print("  review report + markdown rendering ok")


def test_config_round_trip():
    """update's remembered exe/myseq-dir paths -- missing file, merge-not-
    replace on repeated saves, and a corrupt file must never crash the tool,
    just fall back to 'nothing remembered yet'."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "nested", "config.json")
        assert pathconfig.load(path) == {}, "missing file should load empty, not raise"

        pathconfig.save({"exe_path": "/a/eqgame.exe"}, path)
        assert pathconfig.load(path) == {"exe_path": "/a/eqgame.exe"}

        pathconfig.save({"myseq_dir": "/b/myseq"}, path)
        assert pathconfig.load(path) == {"exe_path": "/a/eqgame.exe", "myseq_dir": "/b/myseq"}, \
            "save should merge into the existing file, not replace it"

        with open(path, "w") as fh:
            fh.write("not json{{{")
        assert pathconfig.load(path) == {}, "corrupt file should load empty, not raise"
    print("  config round trip (missing/merge/corrupt) ok")


def test_remembered_path_precedence():
    """--exe/--myseq-dir on the command line always wins; otherwise a still-
    valid remembered path is used silently; a remembered path that no longer
    exists (moved install, reinstalled game) must trigger a re-prompt rather
    than being trusted blindly."""
    with tempfile.TemporaryDirectory() as tmp:
        real = os.path.join(tmp, "real.exe")
        open(real, "w").close()
        missing = os.path.join(tmp, "gone.exe")

        path, ask = _remembered_path(real, missing, os.path.isfile, "exe")
        assert path == real and not ask, "explicit CLI value must win over a remembered one"

        path, ask = _remembered_path(None, real, os.path.isfile, "exe")
        assert path == real and not ask, "a still-valid remembered path should not re-prompt"

        path, ask = _remembered_path(None, missing, os.path.isfile, "exe")
        assert path is None and ask, "a stale remembered path must trigger a re-prompt"

        path, ask = _remembered_path(None, None, os.path.isfile, "exe")
        assert path is None and ask, "nothing given or remembered must prompt"
    print("  remembered-path precedence (cli > valid remembered > reprompt) ok")


def test_build_string_extraction():
    """The BuildString is assembled from three separately-embedded strings
    (a client number inside an unrelated message, plus adjacent __TIME__/
    __DATE__ macro strings) -- this is real regression-prone parsing logic,
    verified against real eqgame.exe binaries during development but tested
    here against a synthetic blob so the suite doesn't depend on a
    copyrighted binary being present."""
    blob = (b"\x00" * 20
            + b"Fatal error occurred in mainthread! (Release Client #630)\x00"
            + b"some unrelated string\x00"
            + b"13:29:05\x00"
            + b"Aug 13 2026\x00"
            + b"\x00" * 20)
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        result = extract_build_string(path)
        assert result == "Release Client #630 13:29:05 Aug 13 2026", result
    finally:
        os.remove(path)

    # No plausible __TIME__/__DATE__ pair -> None, not a guess.
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"Release Client #630 but no date strings nearby\x00")
        assert extract_build_string(path) is None
    finally:
        os.remove(path)
    print("  build string extraction ok")


def test_norm_value_hex_vs_decimal():
    """[WorldInfo Offsets] stores plain decimal ('10'); everything else
    stores hex ('0x4b4'). A blind int(v, 16) misreads '10' as 16 -- this
    guards the fix."""
    assert _norm_value("0x4B4") == _norm_value("0x4b4") == 1204
    assert _norm_value("10") == 10          # not 16
    assert _norm_value("0x10") == 16
    assert _norm_value("garbage") == "garbage"
    print("  _norm_value hex vs decimal ok")


def test_ini_up_to_date_detection():
    """The update command's core decision: does the existing ini already
    match everything eqoffsets can confirm?"""
    memory = {"ZoneAddr": 0x140EBA8F4}
    static = {"SpawnInfo Offsets": {"LevelOffset": "0x210"},
              "WorldInfo Offsets": {"WorldHourOffset": "8"}}

    matching = configparser.ConfigParser()
    matching.read_dict({
        "Memory Offsets": {"ZoneAddr": "0x140eba8f4"},   # case-insensitive
        "SpawnInfo Offsets": {"LevelOffset": "0x210"},
        "WorldInfo Offsets": {"WorldHourOffset": "8"},   # decimal, not hex
    })
    assert _ini_up_to_date(matching, memory, static)

    stale = configparser.ConfigParser()
    stale.read_dict({
        "Memory Offsets": {"ZoneAddr": "0x140eba8f4"},
        "SpawnInfo Offsets": {"LevelOffset": "0x564"},   # old value
        "WorldInfo Offsets": {"WorldHourOffset": "8"},
    })
    assert not _ini_up_to_date(stale, memory, static)

    empty = configparser.ConfigParser()
    assert not _ini_up_to_date(empty, memory, static)
    print("  ini up-to-date detection ok")


def test_latest_pair_picks_newest_date():
    with tempfile.TemporaryDirectory() as tmp:
        known_dir = os.path.join(tmp, "known")
        sigs_dir = os.path.join(tmp, "sigs")
        os.makedirs(known_dir)
        os.makedirs(sigs_dir)
        for d in ("2026-01-01", "2026-08-19"):
            open(os.path.join(known_dir, f"{d}.json"), "w").close()
            open(os.path.join(sigs_dir, f"{d}.json"), "w").close()
        # A known/ entry with no matching sigs/ file must not win.
        open(os.path.join(known_dir, "2026-12-31.json"), "w").close()

        sigs_path, known_path = _latest_pair(known_dir, sigs_dir)
        assert sigs_path.endswith("2026-08-19.json"), sigs_path
        assert known_path.endswith("2026-08-19.json"), known_path
    print("  _latest_pair picks newest common date ok")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"running {len(tests)} tests\n")
    fails = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
            fails += 1
        except Exception as e:
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            fails += 1
    print(f"\n{len(tests) - fails}/{len(tests)} passed")
    sys.exit(1 if fails else 0)
