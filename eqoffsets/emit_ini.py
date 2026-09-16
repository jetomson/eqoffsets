"""Write myseqserver.ini.

The caller (cli.py) assembles `static_sections` before this module ever sees
it: struct member offsets that structsig.py could anchor and confirm are
already overlaid on top of the --known values by the time this function
runs, and anything that could not be confirmed is carried forward from the
known-offsets file. Values arrive pre-formatted in whichever radix their
section uses -- hex for the struct sections, plain decimal for [WorldInfo
Offsets] -- so this module just formats whatever dict it is handed and has no
opinion about where the values came from.
"""

import datetime

MEMORY_ORDER = ["ZoneAddr", "SpawnHeaderAddr", "CharInfo",
                "TargetAddr", "ItemsAddr", "WorldAddr"]

# Published MySEQ lists put the sections in this order. Nothing parses them
# positionally, but keeping a generated file diffable against a published one
# is worth one list.
SECTION_ORDER = ["WorldInfo Offsets", "SpawnInfo Offsets", "GroundItem Offsets"]


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

    ordered_sections = [s for s in SECTION_ORDER if s in static_sections]
    ordered_sections += [s for s in static_sections if s not in SECTION_ORDER]
    for section in ordered_sections:
        lines.append(f"[{section}]")
        for k, v in static_sections[section].items():
            lines.append(f"{k}={v}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_ini(path, *args, **kwargs):
    text = build_ini_text(*args, **kwargs)
    with open(path, "w", newline="\r\n") as fh:
        fh.write(text)
    return text
