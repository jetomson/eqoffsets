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
        self.match_va = {}       # sig_id -> VA where its pattern matched
        self.failures = {}       # sig_id -> reason
        self.value = None
        self.agreement = 0
        self.total = 0
        # sig_id -> width, for dissenting votes apply_width_rule decided not
        # to count against the field. Kept (not deleted from `votes`) so
        # every report still shows them -- discounting is not hiding.
        self.discounted = {}
        # What apply_width_rule saw: {"width", "share", "value", "on_width",
        # "acted"} or None when the rule had nothing to say.
        self.width_info = None

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
        return self.ok and self.agreement == len(self.votes) - len(self.discounted)

    def summary(self):
        if not self.ok:
            return f"{self.name}: FAILED ({len(self.failures)} signature(s) unusable)"
        tag = "unanimous" if self.unanimous else "SPLIT"
        if self.discounted:
            tag += f", {len(self.discounted)} off-width dissent discounted"
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
        # Every signature's pattern starts at its site instruction, so the
        # match offset is also that instruction's address -- exactly where a
        # human would want to look to judge a disagreeing vote by eye.
        res.match_va[sig_id] = sec.va + off

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


# A dissenting vote is discounted only when the field's most common access
# width covers at least this share of its anchored sites. Measured across the
# three boundaries crosscheck had when this was added (07/17 -> 10/19/2026),
# every threshold from 50% to 67% produced zero wrong confirmations; what
# moved was how many UNCONFIRMED fields it rescued. The two fields that
# decide 55% vs 60% vs 67% (HideOffset's pool at 56%, LevelOffset's at 60%)
# are single data points, so picking the cutoff that happens to rescue them
# would be fitting to the very cases being measured. 2/3 acts only where the
# dominant width is unambiguous (NameOffset 91%, GroundItem.IdOffset 76%);
# fields under it get an advisory instead. Revisit with more boundaries.
WIDTH_DOMINANCE = 2 / 3


def width_label(width):
    return "address-of (lea)" if width == "addr" else f"{width}-byte"


def apply_width_rule(res, signatures, mix):
    """Stop off-width dissent from blocking a field whose real accesses agree.

    A struct member is declared with one type, so the code that genuinely
    touches it overwhelmingly does so at one width. A site that reaches the
    same numeric offset at a different width -- `lea rcx, [rdi+0x270]`
    against a field every other site reads as a byte -- is far more likely
    another struct sharing the offset than the field itself. Measured
    across three real boundaries, at every threshold from 50% to 67%, no
    vote this rule would discount was a correct one.

    Deliberately narrow:
      * the reference width comes from the whole anchored pool recorded at
        build time (`mix`, see structsig.width_mix), never from the
        handful of signatures that happened to fire;
      * only votes that *disagree* with the on-width consensus are
        discounted -- an off-width vote that agrees is still support;
      * the on-width votes must themselves be unanimous, or nothing changes;
      * below WIDTH_DOMINANCE the rule only records an advisory for the
        report and leaves the decision exactly as it was;
      * signatures built before widths were recorded leave it inert.
    """
    if not res.ok or not mix:
        return res
    widths = {s.get("id", s["pattern"][:16]): s.get("width") for s in signatures}
    if any(widths.get(sid) is None for sid in res.votes):
        return res

    total = sum(mix.values())
    ref, n_ref = max(mix.items(), key=lambda kv: kv[1])
    share = n_ref / total

    on_width = {sid: v for sid, v in res.votes.items() if widths[sid] == ref}
    if not on_width or len(set(on_width.values())) != 1:
        return res
    value = next(iter(on_width.values()))
    off_dissent = {sid: widths[sid] for sid, v in res.votes.items()
                   if widths[sid] != ref and v != value}
    if not off_dissent:
        return res

    acted = share >= WIDTH_DOMINANCE
    res.width_info = {"width": ref, "share": share, "value": value,
                      "on_width": len(on_width), "acted": acted}
    if acted:
        res.discounted = off_dissent
        res.value = value
        res.agreement = sum(1 for v in res.votes.values() if v == value)
    return res


def width_note(res, format_value):
    """One line explaining what apply_width_rule did, or None."""
    info = res.width_info if res else None
    if not info:
        return None
    width = width_label(info["width"])
    if info["acted"]:
        dissent = ", ".join(f"{sid} ({width_label(w)})" for sid, w in res.discounted.items())
        return (f"discounted off-width dissent: {dissent} -- this field is accessed "
                f"as {width} at {info['share']:.0%} of its anchored sites")
    return (f"advisory only: the {info['on_width']} vote(s) at this field's most common "
            f"width ({width}, {info['share']:.0%} of its anchored sites) all agree on "
            f"{format_value(info['value'])}; below the {WIDTH_DOMINANCE:.0%} needed to "
            f"discount the dissent automatically")


def resolve_struct_all(image, struct_sigs):
    """resolve_all for struct fields, with apply_width_rule on each.

    The one entry point every struct consumer (resolve, update, selftest,
    crosscheck) goes through, so the rule cannot be applied in one place
    and forgotten in another.
    """
    results = resolve_all(image, {"offsets": struct_sigs})
    for key, entry in struct_sigs.items():
        res = results.get(key)
        if res is not None:
            apply_width_rule(res, entry.get("signatures", []), entry.get("width_mix"))
    return results
