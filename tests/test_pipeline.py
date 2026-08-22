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
from eqoffsets.structsig import build_struct_offset_signatures
from eqoffsets.resolve import resolve_offset, resolve_all
from eqoffsets.scan import compile_pattern, find_all, parse_pattern, format_pattern
from eqoffsets.buildinfo import extract_build_string
from eqoffsets.cli import _check_pair, _norm_value, _ini_up_to_date, _latest_pair


class FakeImage:
    """Duck-typed stand-in for PEImage."""

    def __init__(self, text_va, text_bytes, data_va, data_bytes, image_base=0x140000000):
        self.image_base = image_base
        self.size_of_image = 0x2000000
        self.machine = 0x8664
        self.sections = [
            Section(".text", text_va - image_base, text_va, len(text_bytes), text_bytes, True),
            Section(".data", data_va - image_base, data_va, len(data_bytes), data_bytes, False),
        ]

    is_x64 = True

    def exec_sections(self):
        return [s for s in self.sections if s.executable]

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
