"""Decide which `[reg+disp]` sites are really accesses to a struct we care about.

Why this exists
---------------
A struct member offset is a small integer, not part of a unique address.
Searching an 8 MB `.text` for "every instruction touching `[reg+0x4d0]`"
returns dozens of hits belonging to unrelated classes that happen to have a
field at the same numeric offset. Bytes alone cannot tell them apart, and
trusting the wrong one is not hypothetical -- see the HideOffset correction
recorded in `known/2026-08-19.json`, where a byte-identical match across a
patch turned out to be a stack store in an unrelated function.

So we never start from the displacement. We start from something we already
know is a spawn (or ground item, or world-info block) and follow it forward
through the code. A site is *anchored* only if its base register can be
traced back to such a root. Everything else is discarded before a signature
is ever built for it -- an unanchored site does not get to vote, not even as
a minority.

How a register becomes trusted
------------------------------
Five ways, in descending order of how much they deserve to be believed
(`ANCHOR_STRENGTH`):

  root     `mov rcx, [rip+CharInfo]` / `lea rax, [rip+ItemsAddr]` -- the
           register came straight out of an already-resolved global. A
           global may hold a pointer to the struct (the `mov` form) or *be*
           the struct (the `lea` form); both are accepted because which one
           applies is a property of the game's source, not something we get
           to choose, and a wrong guess yields no sites rather than bad ones.

  link     `mov rcx, [rcx+NextOffset]` starting from an already-trusted
           register -- walking the linked list a spawn lives in lands on
           another spawn.

  this     a direct `call` made with a trusted register in rcx means the
           callee's `this` is that struct. Propagated to a fixpoint, this is
           what reaches accessor methods, which is where the interesting
           fields (OwnerID, Hide, the WorldInfo bytes) are actually read.

  linkseed a bare `mov rdx, [rax+PrevOffset]` where `rax` itself was never
           traced to a root. This is the weakest rule and the only one that
           is purely local; it is what the original structsig.py used as its
           sole anchor. Kept because it still reaches real list-walk code
           that the dataflow misses, scored last, and never the only kind of
           evidence a field is accepted on when better evidence exists.

  shape    OFF BY DEFAULT -- a register off which the function accesses
           several *distinct* and *distinctive* known field offsets of the
           same struct. The reasoning is appealing (a function doing
           `[rbx+0x168]` and `[rbx+0xfcc]` is surely handling a spawn) and
           the measurement disagrees: across the 07/17 -> 08/19/2026
           boundary, shape-anchored signatures survived 52% of the time at
           `SHAPE_MIN_FIELDS=2` and 82% at 4, against 95-100% for every
           dataflow anchor above. Worse, its mistakes are not random -- they
           are concentrated in initialiser functions that write many fields
           at once and did not change across the patch, so a shape-anchored
           signature fails specifically by insisting a field that *moved*
           stayed put. That is the exact shape of the HideOffset error this
           module exists to prevent. Turning it off cost no coverage at all
           (all 31 fields still resolved correctly) and removed nearly all
           dissent, so it is opt-in via `enable_shape=True` for the case
           where a future patch loses dataflow coverage and weak evidence
           beats none.

Being anchored gets a site into the candidate pool. It is not the final
word: the site still has to yield a byte signature that matches exactly once
in the source binary, and the signatures still have to agree with each other
on the new binary before anything is emitted.

Calibration caveat: the survival percentages above come from a single patch
boundary, the only one this repository has both binaries for. They are
enough to rank the anchor kinds -- the gap between 52% and 100% is not
noise -- but they are not enough to fine-tune anything. Re-measure with
`cli.py crosscheck` as more patch pairs are collected.
"""

from capstone.x86 import X86_OP_IMM, X86_OP_REG

from .codemap import CodeMap, RCX, VOLATILE_FAMILIES
from .refs import rip_target

# Higher is more trustworthy; see the module docstring for the reasoning.
ANCHOR_STRENGTH = {"root": 5, "link": 4, "this": 3, "shape": 2, "linkseed": 1}

# When shape anchoring is enabled at all, how many distinct distinctive field
# offsets a register must be used with before the function is believed to be
# handling that struct. 2 measured at 52% survival, 3 at 63%, 4 at 82%; the
# default is the strictest of those that still yields usable site counts.
SHAPE_MIN_FIELDS = 4

# Offsets below this are too common to be evidence of anything -- 0x8, 0x10,
# 0x18 and friends are the first few members of nearly every class in the
# binary.
SHAPE_MIN_DISP = 0x80

# Bound on `this`-propagation rounds. In practice eqgame.exe reaches a
# fixpoint in 4; the cap only exists so a pathological call graph cannot
# spin forever.
MAX_ROUNDS = 8

# Mnemonics that move a value into a register without transforming it, so
# trust carries across them.
COPY_MNEMONICS = frozenset({"mov", "lea", "movzx", "movsxd", "movsx"})
LOAD_MNEMONICS = frozenset({"mov", "movzx", "movsxd", "movsx"})


class StructKind:
    """One struct layout we want offsets for, and how to reach an instance.

    `field_disps` are the *currently known* offsets of this struct's members,
    used only to recognise the struct's shape in code; they are never the
    source of a derived answer.
    """

    def __init__(self, name, root_globals=(), link_disps=(), field_disps=()):
        self.name = name
        self.root_globals = frozenset(root_globals)
        self.link_disps = frozenset(link_disps)
        self.field_disps = frozenset(field_disps)
        self.shape_disps = frozenset()   # filled in by distinctive_disps()

    def __repr__(self):
        return (f"<StructKind {self.name} roots={len(self.root_globals)} "
                f"links={len(self.link_disps)} fields={len(self.field_disps)}>")


def distinctive_disps(kinds):
    """Assign each kind the field offsets that identify *it* and nothing else.

    An offset shared by two struct layouts proves nothing about which one a
    register points at -- SpawnInfo.SpeedOffset and GroundItem.XOffset are
    both 0x8c, so code touching 0x8c and 0x90 fits either shape equally well.
    Shared offsets are therefore dropped from every kind's shape set rather
    than left to contaminate both.
    """
    seen = {}
    for kind in kinds:
        for disp in kind.field_disps:
            seen[disp] = seen.get(disp, 0) + 1
    for kind in kinds:
        kind.shape_disps = frozenset(
            d for d in kind.field_disps if d >= SHAPE_MIN_DISP and seen[d] == 1
        )
    return kinds


class AnchoredSite:
    __slots__ = ("kind", "va", "disp", "disp_off", "disp_size",
                 "fn_start", "fn_end", "anchor", "text", "is_write")

    def __init__(self, kind, access, fn_start, fn_end, anchor):
        self.kind = kind
        self.va = access.va
        self.disp = access.disp
        self.disp_off = access.disp_off
        self.disp_size = access.disp_size
        self.fn_start = fn_start
        self.fn_end = fn_end
        self.anchor = anchor
        self.text = access.text
        self.is_write = access.is_write

    @property
    def strength(self):
        return ANCHOR_STRENGTH.get(self.anchor, 0)

    def __repr__(self):
        return f"<AnchoredSite {self.kind} 0x{self.va:X} +0x{self.disp:X} {self.anchor}>"


def _shape_taint(codemap, insns, kinds):
    """{reg_family: {kind_name: 'shape'}} for registers this function treats
    as a known struct, judged purely by which field offsets it touches."""
    seen = {}
    for insn in insns:
        for acc in codemap.mem_accesses(insn):
            for kind in kinds:
                if acc.disp in kind.shape_disps:
                    seen.setdefault(acc.base_family, {}).setdefault(kind.name, set()).add(acc.disp)
    out = {}
    for fam, per_kind in seen.items():
        for kind_name, disps in per_kind.items():
            if len(disps) >= SHAPE_MIN_FIELDS:
                out.setdefault(fam, {})[kind_name] = "shape"
    return out


def _stronger(a, b):
    return a if ANCHOR_STRENGTH.get(a, 0) >= ANCHOR_STRENGTH.get(b, 0) else b


def _merge(into, extra):
    for kind_name, anchor in extra.items():
        cur = into.get(kind_name)
        into[kind_name] = anchor if cur is None else _stronger(cur, anchor)


def analyze_function(codemap, fn_start, fn_end, kinds, entry_taint, want,
                     insns=None, enable_shape=False):
    """Walk one function forward, recording anchored sites and callee `this` taint.

    Returns (sites, call_taints) where call_taints is {callee_va: {kind: anchor}}.
    """
    insns = codemap.instructions(fn_start, fn_end) if insns is None else insns
    if not insns:
        return [], {}

    by_name = {k.name: k for k in kinds}
    shape = _shape_taint(codemap, insns, kinds) if enable_shape else {}

    # taint[reg_family] = {kind_name: anchor_label}
    taint = {}
    if entry_taint:
        taint[RCX] = dict(entry_taint)

    sites = []
    call_taints = {}

    for insn in insns:
        accesses = codemap.mem_accesses(insn)

        # --- record: any access off a register we trust -----------------
        for acc in accesses:
            trusted = dict(taint.get(acc.base_family, {}))
            _merge(trusted, shape.get(acc.base_family, {}))
            if not trusted:
                continue
            for kind_name, anchor in trusted.items():
                wanted = want.get(kind_name)
                if wanted is not None and acc.disp not in wanted:
                    continue
                sites.append(AnchoredSite(kind_name, acc, fn_start, fn_end, anchor))

        # --- propagate `this` into direct calls -------------------------
        ops = insn.operands
        if insn.mnemonic == "call" and ops and ops[0].type == X86_OP_IMM:
            passed = dict(taint.get(RCX, {}))
            _merge(passed, shape.get(RCX, {}))
            if passed:
                target = ops[0].imm
                slot = call_taints.setdefault(target, {})
                _merge(slot, {k: "this" for k in passed})

        # --- transfer: what does this instruction put into a register? --
        produced = {}
        mnem = insn.mnemonic

        if mnem in ("mov", "lea"):
            target_va = rip_target(insn)
            if target_va is not None:
                for kind in kinds:
                    if target_va in kind.root_globals:
                        _merge(produced, {kind.name: "root"})

        if mnem in LOAD_MNEMONICS:
            for acc in accesses:
                if acc.is_write:
                    continue
                src_taint = taint.get(acc.base_family, {})
                for kind_name, anchor in src_taint.items():
                    kind = by_name.get(kind_name)
                    if kind and acc.disp in kind.link_disps:
                        _merge(produced, {kind_name: "linkseed" if anchor == "linkseed" else "link"})
                if not src_taint:
                    # The list-walk shape on its own, with nothing behind it.
                    # Weakest anchor we accept; see the module docstring.
                    for kind in kinds:
                        if acc.disp in kind.link_disps:
                            _merge(produced, {kind.name: "linkseed"})

        if mnem in COPY_MNEMONICS and len(ops) > 1 and ops[1].type == X86_OP_REG:
            src_fam = codemap.reg_family.get(ops[1].reg)
            if src_fam is not None:
                _merge(produced, taint.get(src_fam, {}))

        dest = codemap.dest_register_family(insn)
        if dest is not None:
            if produced:
                taint[dest] = produced
            else:
                # Any other definition of the register destroys what we knew.
                taint.pop(dest, None)

        if mnem == "call":
            for fam in VOLATILE_FAMILIES:
                taint.pop(fam, None)

    return sites, call_taints


def find_anchored_sites(image, kinds, want=None, codemap=None, verbose=False,
                        enable_shape=False):
    """{kind_name: {disp: [AnchoredSite]}} for every anchored access in the image.

    `want` optionally restricts which displacements are recorded, as
    {kind_name: set(disp)} -- callers know which fields they are after, and
    keeping only those is the difference between a few thousand sites and a
    few million.
    """
    codemap = codemap or CodeMap(image)
    kinds = distinctive_disps(list(kinds))
    want = want or {}

    fn_index = {start: (start, end) for start, end in codemap.functions}
    entry_taint = {}          # fn_start -> {kind: anchor}
    found = {}                # (kind, va, disp) -> AnchoredSite
    # Round 0 has to visit everything, since trust can start anywhere a root
    # global is referenced. After that only functions whose entry taint just
    # changed can produce anything new, and that set shrinks fast -- on
    # eqgame.exe it goes 26.6k -> ~760 -> ~85 -> converged.
    pending = None            # None means "all of them"

    for round_no in range(MAX_ROUNDS):
        targets = codemap.functions if pending is None else sorted(pending)
        new_entry = {}
        n_sites = 0
        for fn_start, fn_end in targets:
            sites, call_taints = analyze_function(
                codemap, fn_start, fn_end, kinds, entry_taint.get(fn_start), want,
                enable_shape=enable_shape)
            for site in sites:
                key = (site.kind, site.va, site.disp)
                prev = found.get(key)
                if prev is None or site.strength > prev.strength:
                    found[key] = site
            n_sites += len(sites)
            for callee, kinds_map in call_taints.items():
                if callee not in fn_index:
                    continue        # call into a thunk or an import, not a body we can walk
                merged = dict(new_entry.get(callee) or entry_taint.get(callee, {}))
                before = dict(merged)
                _merge(merged, kinds_map)
                if merged != before:
                    new_entry[callee] = merged

        if verbose:
            scope = "all functions" if pending is None else f"{len(targets)} function(s)"
            print(f"    anchor round {round_no}: {scope}, {n_sites} site(s), "
                  f"{len(new_entry)} newly-trusted callee(s)")

        if not new_entry:
            break

        entry_taint.update(new_entry)
        pending = {fn_index[callee] for callee in new_entry}

    out = {}
    for site in found.values():
        out.setdefault(site.kind, {}).setdefault(site.disp, []).append(site)
    for per_disp in out.values():
        for site_list in per_disp.values():
            site_list.sort(key=lambda s: (-s.strength, s.va))
    return out
