"""Sanity checks on resolved addresses.

Never emit an offset you have not argued with. A signature that matched the
wrong instruction usually produces an address that is obviously wrong once
you ask two or three cheap questions about it -- and catching it here is the
difference between "the tool told me it failed" and "you spent an evening
wondering why the radar shows nothing".
"""

DATA_SECTIONS = (".data", ".rdata", ".bss", ".pdata")


def validate_offset(image, name, value, known_cluster=None):
    problems = []
    warnings = []

    if not image.in_image(value):
        problems.append(f"0x{value:X} is outside the image "
                        f"(0x{image.image_base:X}..0x{image.image_base + image.size_of_image:X})")
        return problems, warnings

    sec = image.section_for_va(value)
    if sec is None:
        problems.append(f"0x{value:X} is not inside any section")
        return problems, warnings

    if sec.executable:
        problems.append(f"0x{value:X} lands in executable section {sec.name}; "
                        f"a data global should not live in code")
    elif sec.name not in DATA_SECTIONS:
        warnings.append(f"0x{value:X} is in unusual section {sec.name}")

    if known_cluster:
        spread = max(abs(value - other) for other in known_cluster)
        if spread > 0x400000:  # 4 MB
            warnings.append(f"0x{value:X} sits {spread / 1024 / 1024:.1f} MB from the "
                            f"other globals; they normally cluster together")

    return problems, warnings


def validate_struct_offset(name, value, max_size=0x10000):
    """Sanity check for a derived struct member offset (not an address).

    There is no section/cluster check available here -- a struct offset is
    just a small integer -- so this is intentionally weaker than
    validate_offset. The real safety net for struct offsets is the anchoring
    in structsig.py, which decides what gets to vote in the first place;
    this only catches the case where anchoring somehow still produced
    nonsense (negative, or bigger than any real struct in this game).
    """
    problems = []
    if value is None:
        return ["unresolved"]
    if value < 0 or value >= max_size:
        problems.append(f"0x{value:X} is outside the plausible struct-size range "
                        f"(0..0x{max_size:X})")
    return problems


def validate_all(image, resolutions):
    values = [r.value for r in resolutions.values() if r.ok]
    report = {}
    for name, r in resolutions.items():
        if not r.ok:
            report[name] = (["unresolved"], [])
            continue
        others = [v for v in values if v != r.value]
        report[name] = validate_offset(image, name, r.value, known_cluster=others)
    return report


def print_report(resolutions, report):
    print("\n--- resolution ---")
    for name, r in resolutions.items():
        print(" ", r.summary())
        for sig_id, reason in r.failures.items():
            print(f"      - {sig_id}: {reason}")

    print("\n--- validation ---")
    clean = True
    for name, (problems, warnings) in report.items():
        for p in problems:
            print(f"  ERROR {name}: {p}")
            clean = False
        for w in warnings:
            print(f"  warn  {name}: {w}")
    if clean:
        print("  all resolved addresses passed structural checks")
    return clean
