"""Wildcard byte-pattern scanning.

Patterns are stored in JSON as IDA-style strings:

    "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"

'??' means "any byte". Matching is done by anchoring on the longest run of
concrete bytes and using bytes.find() to skip ahead, which is dramatically
faster than a naive per-offset loop over a 20 MB .text section.
"""


def parse_pattern(text):
    """'48 8B ?? C0' -> (b'\\x48\\x8b\\x00\\xc0', 'xx?x')"""
    tokens = text.split()
    pat = bytearray()
    mask = []
    for t in tokens:
        if t in ("??", "?"):
            pat.append(0)
            mask.append("?")
        else:
            pat.append(int(t, 16))
            mask.append("x")
    return bytes(pat), "".join(mask)


def format_pattern(pat, mask):
    out = []
    for b, m in zip(pat, mask):
        out.append("??" if m == "?" else f"{b:02X}")
    return " ".join(out)


def longest_concrete_run(mask):
    """Return (offset, length) of the longest run of 'x' in the mask."""
    best_off, best_len = 0, 0
    cur_off, cur_len = 0, 0
    for i, m in enumerate(mask):
        if m == "x":
            if cur_len == 0:
                cur_off = i
            cur_len += 1
            if cur_len > best_len:
                best_off, best_len = cur_off, cur_len
        else:
            cur_len = 0
    return best_off, best_len


class CompiledPattern:
    """Pre-chewed pattern: anchor plus the residual concrete byte checks."""

    def __init__(self, pat, mask):
        self.pat = pat
        self.mask = mask
        self.length = len(pat)
        self.anchor_off, self.anchor_len = longest_concrete_run(mask)
        self.anchor = pat[self.anchor_off:self.anchor_off + self.anchor_len]
        # Every concrete byte NOT covered by the anchor still has to be verified.
        self.checks = [
            (i, pat[i])
            for i in range(self.length)
            if mask[i] == "x" and not (self.anchor_off <= i < self.anchor_off + self.anchor_len)
        ]

    @property
    def wildcard_count(self):
        return self.mask.count("?")

    def __repr__(self):
        return f"<CompiledPattern len={self.length} anchor={self.anchor_len}>"


def compile_pattern(text):
    pat, mask = parse_pattern(text)
    return CompiledPattern(pat, mask)


def find_all(data, compiled, limit=None):
    """Return byte offsets into `data` where the pattern matches.

    `limit` stops early -- pass limit=2 when all you need to know is
    'is this pattern unique?', which is the common case during signature
    building and is what keeps build times sane.
    """
    if compiled.anchor_len == 0:
        raise ValueError("pattern has no concrete bytes; refusing to scan")

    results = []
    anchor = compiled.anchor
    anchor_off = compiled.anchor_off
    checks = compiled.checks
    total = compiled.length
    n = len(data)
    pos = 0

    while True:
        i = data.find(anchor, pos)
        if i < 0:
            break
        pos = i + 1
        start = i - anchor_off
        if start < 0 or start + total > n:
            continue
        ok = True
        for off, val in checks:
            if data[start + off] != val:
                ok = False
                break
        if ok:
            results.append(start)
            if limit is not None and len(results) >= limit:
                break
    return results


def is_unique(data, compiled):
    return len(find_all(data, compiled, limit=2)) == 1
