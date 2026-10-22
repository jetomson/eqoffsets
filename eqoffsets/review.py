"""Builds a human-reviewable record of struct fields resolve/update could
not confirm on its own.

"Never emit an unvalidated address" (CLAUDE.md invariant #4) means a field
that ends in real disagreement never gets auto-applied. But going silent
about it isn't good enough either: the whole point of this project is not
waiting days for someone else to publish a corrected offset list, so an
UNCONFIRMED (or BEST-EFFORT) field needs to hand whoever is running the tool
everything a person would need to settle it themselves -- which values are
competing, how many signatures (and how strong an anchor) backed each one,
and the actual surrounding code for each candidate in both the old binary
(where it was derived) and the new one (where it's being applied), side by
side. That last part automates the same "eyeball the disassembly" technique
known/2026-08-19.json's provenance describes doing by hand, and is usually
what turns an UNCONFIRMED field into a ten-second decision instead of a
multi-day wait.

cli.py's console output and the Markdown file this module writes are built
from the exact same report dicts (see build_field_report), so the two can
never end up saying different things about the same field.
"""

import datetime


def gather_candidates(r, signatures):
    """One entry per distinct voted value, most-voted first.

    Grouping by value rather than listing every signature is deliberate --
    several signatures voting the same value are the same code shape by
    construction (a struct field only has one true location), so showing
    all of them would just repeat the same evidence. What a person needs is
    each *candidate answer*, once, to compare against the others.
    """
    if not r or not r.votes:
        return []
    sig_by_id = {s.get("id", s["pattern"][:16]): s for s in signatures}
    by_value = {}
    for sid, val in r.votes.items():
        by_value.setdefault(val, []).append(sid)

    candidates = []
    for val, sids in by_value.items():
        rep_sig = sig_by_id.get(sids[0], {})
        candidates.append({
            "value": val,
            "sids": sids,
            "rep": sids[0],
            "anchor": rep_sig.get("anchor", "?"),
            "match_va": r.match_va.get(sids[0]),
            "old_site_va": rep_sig.get("site_va"),
        })
    candidates.sort(key=lambda c: -len(c["sids"]))
    return candidates


def _window_lines(codemap, va):
    """[str] of one disassembly window, or None if it can't be recovered."""
    if codemap is None or va is None:
        return None
    insns = codemap.disasm_window(va)
    if not insns:
        return None
    lines = []
    for insn in insns:
        marker = "->" if insn.address == va else "  "
        lines.append(f"{marker} 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}".rstrip())
    return lines


def build_field_report(label, r, radix, signatures, format_disp, codemap, old_codemap,
                       known_val, status, why, applied_val=None, width_note=None):
    """Everything needed to describe one struct field's outcome to both the
    console and the review doc.

    `status` is "unconfirmed" or "best_effort" -- confirmed fields never
    reach this function, since there is nothing to review about them.
    `known_val` is whatever was on file before this run; `applied_val` is
    what's actually in use now -- for "unconfirmed" that's the same
    carried-forward value, but for "best_effort" it's the plurality vote
    that got applied, which the report needs to call out as distinct from
    the value it displaced.

    `codemap` disassembles in the binary being resolved against;
    `old_codemap` (optional -- None when the original binary has moved,
    been deleted, or changed) disassembles in the binary signatures were
    built from, for the side-by-side comparison.

    `width_note` is resolve.width_note()'s line about access widths, if the
    width check had anything to say -- below its threshold that is often
    the single most useful hint a reviewer gets.
    """
    candidates = gather_candidates(r, signatures)
    for c in candidates:
        c["value_str"] = format_disp(c["value"], radix)
        c["new_window"] = _window_lines(codemap, c["match_va"])
        old_va = c.get("old_site_va")
        if isinstance(old_va, str):
            old_va = int(old_va, 16)
        c["old_window"] = _window_lines(old_codemap, old_va)

    return {
        "label": label,
        "known_val": known_val,
        "applied_val": applied_val if applied_val is not None else known_val,
        "status": status,
        "why": why,
        "width_note": width_note,
        "candidates": candidates,
        "failures": dict(r.failures) if r else {},
    }


def build_markdown(reports, meta=None):
    """Render `reports` (from build_field_report) as a standalone Markdown
    document. Returns the text; write_markdown below saves it to disk.
    """
    meta = meta or {}
    lines = ["# eqoffsets manual review", ""]
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    binary_note = f" against `{meta['binary']}`" if meta.get("binary") else ""
    lines.append(f"Generated {stamp}{binary_note}.")
    lines.append("")

    if not reports:
        lines.append("Nothing needs manual review -- every struct field either confirmed "
                      "with no dissent or wasn't derivable at all.")
        return "\n".join(lines) + "\n"

    lines.append(
        "The field(s) below could not be confirmed automatically this run: their "
        "anchored signatures either disagreed with each other, or none of them "
        "matched at all. eqoffsets never guesses a value it can't back up -- see "
        "the README section \"Resolving an UNCONFIRMED field yourself\" for the "
        "full explanation. Everything below is what you need to decide by hand, "
        "without waiting on someone else to publish a corrected list."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| field | status | value in use now | candidates (votes) |")
    lines.append("|---|---|---|---|")
    for rep in reports:
        cand_str = ", ".join(f"`{c['value_str']}` ({len(c['sids'])})"
                             for c in rep["candidates"]) or "none matched"
        lines.append(f"| `{rep['label']}` | {rep['status'].upper().replace('_', '-')} "
                     f"| `{rep['applied_val']}` | {cand_str} |")
    lines.append("")

    for rep in reports:
        lines.append(f"## {rep['label']}")
        lines.append("")
        lines.append(f"- status: **{rep['status'].upper().replace('_', '-')}**")
        lines.append(f"- reason: {rep['why']}")
        if rep.get("width_note"):
            lines.append(f"- width check: {rep['width_note']}")
        if rep["status"] == "best_effort" and rep["applied_val"] != rep["known_val"]:
            lines.append(f"- value applied (BEST-EFFORT, not independently confirmed): "
                         f"`{rep['applied_val']}` (was `{rep['known_val']}`)")
        else:
            lines.append(f"- value currently in use (carried forward, unconfirmed): "
                         f"`{rep['known_val']}`")
        lines.append("")
        if not rep["candidates"]:
            lines.append("No signature matched at all in this binary -- there is nothing to "
                         "compare here; this field needs a fresh manual derivation.")
            lines.append("")
        for c in rep["candidates"]:
            lines.append(f"### candidate `{c['value_str']}` -- "
                         f"{len(c['sids'])} vote(s): {', '.join(c['sids'])} [{c['anchor']}]")
            lines.append("")
            if c["old_window"]:
                lines.append("old binary, as originally derived:")
                lines.append("")
                lines.append("```")
                lines.extend(c["old_window"])
                lines.append("```")
                lines.append("")
            if c["new_window"]:
                lines.append("this binary:")
                lines.append("")
                lines.append("```")
                lines.extend(c["new_window"])
                lines.append("```")
                lines.append("")
            if not c["old_window"] and not c["new_window"]:
                lines.append("_(could not recover disassembly context for this candidate)_")
                lines.append("")
        if rep["failures"]:
            lines.append("<details><summary>signature(s) that didn't match at all</summary>")
            lines.append("")
            for sid, reason in rep["failures"].items():
                lines.append(f"- `{sid}`: {reason}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    lines.append("## How to resolve this by hand")
    lines.append("")
    lines.append(
        "1. For each field above, compare the old/new code windows for each "
        "candidate -- look for a byte-identical continuation of the same "
        "instruction sequence, just with the field's own displacement changed. "
        "That is usually enough to tell which candidate is real and which is a "
        "stale or coincidental match."
    )
    lines.append(
        "2. Once you're confident, edit your known-offsets file "
        "(`known/<date>.json`) and set that field to the value you picked."
    )
    lines.append(
        "3. Re-run `resolve` or `update` -- a carried-forward value is only "
        "ever a starting point, never a final answer."
    )
    lines.append(
        "4. If the code alone doesn't settle it (multiple candidates look like "
        "equally clean continuations -- this happens, see the HideOffset example "
        "in the README), you likely need to go one level deeper -- e.g. "
        "disassemble what a nearby `call` target actually does -- or wait for "
        "independent confirmation after all."
    )
    lines.append("")
    lines.append(
        "Alternatively, re-run with `--best-effort` to have the tool apply the "
        "plurality vote automatically instead of asking. Read its `--help` text "
        "first -- it states a measured real case where the plurality was wrong, "
        "not a theoretical caveat."
    )
    return "\n".join(lines) + "\n"


def write_markdown(path, reports, meta=None):
    text = build_markdown(reports, meta)
    with open(path, "w") as fh:
        fh.write(text)
    return text
