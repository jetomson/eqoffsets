"""Write myseqserver.ini.

The caller (cli.py) assembles `static_sections` before this module ever sees
it: struct member offsets that structsig.py could anchor and confirm are
already overlaid on top of the --known values by the time this function
runs, and [WorldInfo Offsets] (bit positions in a packed bitfield, not struct
displacements -- see README "Known limits") is always copied through as-is.
This module just formats whatever dict it's handed; it has no opinion about
where the values came from.
"""

import datetime

MEMORY_ORDER = ["ZoneAddr", "SpawnHeaderAddr", "CharInfo",
                "TargetAddr", "ItemsAddr", "WorldAddr"]


def build_ini_text(memory_offsets, static_sections, patch_date=None, port=5555,
                   build_string=None, client_hash=None):
    patch_date = patch_date or datetime.date.today().strftime("%m/%d/%Y")
    lines = []

    lines.append("[File Info]")
    lines.append(f"PatchDate={patch_date}")
    if client_hash:
        lines.append(f"ClientHash={client_hash}")
    if build_string:
        lines.append(f"BuildString={build_string}")
    lines.append("")

    lines.append("[Port]")
    lines.append(f"port={port}")
    lines.append("")

    lines.append("[Memory Offsets]")
    ordered = [k for k in MEMORY_ORDER if k in memory_offsets]
    ordered += [k for k in memory_offsets if k not in MEMORY_ORDER]
    for key in ordered:
        lines.append(f"{key}=0x{memory_offsets[key]:X}")
    lines.append("")

    for section, values in static_sections.items():
        lines.append(f"[{section}]")
        for k, v in values.items():
            lines.append(f"{k}={v}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_ini(path, *args, **kwargs):
    text = build_ini_text(*args, **kwargs)
    with open(path, "w", newline="\r\n") as fh:
        fh.write(text)
    return text
