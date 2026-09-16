"""Remembers the paths `update` needs so it doesn't have to ask every run.

Stored as a plain JSON file at ~/.eqoffsets/config.json by default -- there
are exactly two values worth remembering (the eqgame.exe path and the MySEQ
install folder), which isn't enough to justify pulling in a config-file
library for it.

An explicit --exe/--myseq-dir on the command line always wins for that run
AND becomes the new remembered value, so pointing the tool at a different
install once is enough -- you don't have to keep passing it, and you don't
have to edit this file by hand to change it. Delete the file (or point
--config at an empty path) to forget everything and go back to being asked.
"""

import json
import os

DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".eqoffsets", "config.json")


def load(path=DEFAULT_PATH):
    """Return the stored dict, or {} if there's nothing usable yet.

    A missing or unreadable file is not an error -- it just means nothing
    has been remembered yet, which is the normal state on a first run.
    """
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save(updates, path=DEFAULT_PATH):
    """Merge `updates` into whatever's already stored and write it back.

    Written to a temp file and renamed into place so a crash mid-write never
    leaves a truncated, unreadable config behind.
    """
    current = load(path)
    current.update(updates)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(current, fh, indent=2)
    os.replace(tmp, path)
    return current
