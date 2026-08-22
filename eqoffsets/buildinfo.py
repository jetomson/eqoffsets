"""Best-effort extraction of ClientHash / BuildString straight from eqgame.exe.

Pure Python -- no dependency on an external `strings` tool -- because this
needs to run on a friend's Windows machine where nothing but this package
and its pip dependencies is guaranteed to exist.

ClientHash turns out to just be sha1 of the whole file (confirmed against a
real published myseqserver.ini -- see known/2026-08-19.json's provenance).
BuildString is assembled from three separate compiler-embedded strings that
are not stored together: a "Release Client #NNN" fragment that lives inside
an unrelated fatal-error message, and the __TIME__/__DATE__ macro strings
(adjacent to each other in the binary, in that order, with only a null
terminator between them -- that is how MSVC lays out consecutive string
literals from the same translation unit). If any piece can't be found this
returns None -- callers should fall back to a known-good value and say so,
not guess.
"""

import hashlib
import re

_TIME_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")
_DATE_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}$")
_NUM_RE = re.compile(r"Release Client #(\d+)")
_MAX_GAP = 8  # bytes allowed between the adjacent __TIME__/__DATE__ strings


def client_hash(path):
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def extract_build_string(path):
    with open(path, "rb") as fh:
        data = fh.read()

    strings = [(m.start(), m.group().decode("ascii"))
               for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]

    num = None
    for _, s in strings:
        m = _NUM_RE.search(s)
        if m:
            num = m.group(1)
            break

    time_date = None
    for off, s in strings:
        if not _TIME_RE.match(s):
            continue
        for off2, s2 in strings:
            gap = off2 - (off + len(s))
            if 0 < gap <= _MAX_GAP and _DATE_RE.match(s2):
                time_date = (s, s2)
                break
        if time_date:
            break

    if not (num and time_date):
        return None
    return f"Release Client #{num} {time_date[0]} {time_date[1]}"
