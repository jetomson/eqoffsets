"""Apply a signature database to a new binary and recover the addresses.

Each offset carries several independent signatures. They should all agree.
When they do not, that is information, not an inconvenience -- it means the
binary changed in a way that broke at least one pattern, and you want the
tool to say so loudly rather than silently pick one and hand you a config
that half works.
"""

import struct
from collections import Counter

from .scan import compile_pattern, find_all


class Resolution:
    def __init__(self, name):
        self.name = name
        self.votes = {}          # sig_id -> value
        self.failures = {}       # sig_id -> reason
        self.value = None
        self.agreement = 0
        self.total = 0

    @property
    def ok(self):
        return self.value is not None

    @property
    def unanimous(self):
        return self.total > 0 and self.agreement == self.total

    @property
    def consistent(self):
        """True if every signature that actually matched agrees with the
        others. Unlike `unanimous`, this does not penalize a signature that
        simply failed to fire -- code drift between patches routinely knocks
        out a few fingerprints without the survivors disagreeing about
        anything, which is a different (and much less worrying) situation
        than signatures actively voting for different values. See
        known/2026-08-19.json's crosscheck history: 'SPLIT' from attrition
        alone has so far always resolved to the correct value once checked
        against a published list; real disagreement is the case worth
        distrusting.
        """
        return self.ok and self.agreement == len(self.votes)

    def summary(self):
        if not self.ok:
            return f"{self.name}: FAILED ({len(self.failures)} signature(s) unusable)"
        tag = "unanimous" if self.unanimous else "SPLIT"
        return (f"{self.name}: 0x{self.value:X} "
                f"[{self.agreement}/{self.total} agree, {tag}]")


def _extract(image, sec, match_off, sig):
    match_va = sec.va + match_off
    kind = sig.get("extract", "rip_target")

    if kind == "rip_target":
        disp_off = sig["disp_off"]
        raw = sec.data[match_off + disp_off:match_off + disp_off + 4]
        if len(raw) < 4:
            return None
        disp = struct.unpack("<i", raw)[0]
        return match_va + sig["insn_len"] + disp

    if kind == "insn_disp":
        # Structure member offset, e.g. the 0x564 in `mov eax, [rcx+0x564]`.
        off = sig["disp_off"]
        size = sig.get("disp_size", 4)
        raw = sec.data[match_off + off:match_off + off + size]
        if len(raw) < size:
            return None
        fmt = {1: "<b", 2: "<h", 4: "<i"}[size]
        return struct.unpack(fmt, raw)[0]

    if kind == "imm":
        off = sig["imm_off"]
        size = sig.get("imm_size", 4)
        raw = sec.data[match_off + off:match_off + off + size]
        if len(raw) < size:
            return None
        fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size]
        return struct.unpack(fmt, raw)[0]

    return None


def resolve_offset(image, name, signatures):
    res = Resolution(name)
    text_sections = image.exec_sections()

    for sig in signatures:
        sig_id = sig.get("id", sig["pattern"][:16])
        res.total += 1
        try:
            compiled = compile_pattern(sig["pattern"])
        except ValueError as e:
            res.failures[sig_id] = str(e)
            continue

        hits = []
        for sec in text_sections:
            for off in find_all(sec.data, compiled, limit=3):
                hits.append((sec, off))
            if len(hits) > 1:
                break

        if not hits:
            res.failures[sig_id] = "no match"
            continue
        if len(hits) > 1:
            res.failures[sig_id] = f"ambiguous ({len(hits)}+ matches)"
            continue

        sec, off = hits[0]
        value = _extract(image, sec, off, sig)
        if value is None:
            res.failures[sig_id] = "extraction failed"
            continue
        res.votes[sig_id] = value

    if res.votes:
        counts = Counter(res.votes.values())
        value, agreement = counts.most_common(1)[0]
        res.value = value
        res.agreement = agreement

    return res


def resolve_all(image, sigdb):
    results = {}
    for name, entry in sigdb["offsets"].items():
        results[name] = resolve_offset(image, name, entry.get("signatures", []))
    return results
