"""Function boundaries and correctly-aligned disassembly.

Everything else in this project scans for *byte patterns*, which needs no
notion of where instructions start. Struct member offsets do: to decide
whether `[rcx+0x4d0]` is a spawn field or an unrelated struct's field, you
have to follow what got loaded into rcx, and following anything means
decoding the surrounding code at the right alignment. Start one byte late
and you get a plausible-looking but entirely fictional instruction stream.

A 64-bit PE hands us that alignment for free. The `.pdata` section is the
image's own exception-unwind table: an array of RUNTIME_FUNCTION records,
each `{begin_rva, end_rva, unwind_rva}`, one per function the compiler
emitted. On eqgame.exe it covers ~94% of `.text` across ~26k functions.
That is an exact, compiler-authored function map -- strictly better than
guessing boundaries from runs of 0xCC padding, which is what structsig.py
used to do and which silently gives up whenever a function is preceded by
alignment bytes that are not 0xCC.

For duck-typed images with no `.pdata` (the synthetic ones in the test
suite), we fall back to treating each executable section as a single span
decoded from its start. That is only sound because those images are built
to be linearly decodable; it is not a strategy that would work on a real
binary, which is exactly why `.pdata` is the primary path.
"""

import bisect
import struct

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from .refs import make_disassembler

RUNTIME_FUNCTION_SIZE = 12

# x86-64 GPRs grouped by family (same architectural register, different
# operand widths) so that rcx/ecx/cx/cl all compare equal. Capstone gives
# every width its own X86_REG_* constant and offers no family lookup, so we
# build one once from the register names.
REG_FAMILIES = [
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
]
REG_FAMILIES += [(f"r{n}", f"r{n}d", f"r{n}w", f"r{n}b") for n in range(8, 16)]

REG_FAMILY_BY_NAME = {name: i for i, fam in enumerate(REG_FAMILIES) for name in fam}
FAMILY_NAME = [fam[0] for fam in REG_FAMILIES]

RAX = REG_FAMILY_BY_NAME["rax"]
RCX = REG_FAMILY_BY_NAME["rcx"]
RSP = REG_FAMILY_BY_NAME["rsp"]
RBP = REG_FAMILY_BY_NAME["rbp"]

# rsp/rbp are never treated as struct base registers. `[rsp+0x48]` is a stack
# slot, and MSVC frames routinely put locals at displacements that collide
# with real struct member offsets. This is not a theoretical tidiness rule:
# the published-list correction recorded in known/2026-08-19.json traces back
# to trusting `mov qword ptr [rbp+0x4d0], rsi` -- a stack store -- as evidence
# about SpawnInfo::Hide. Excluding both registers costs us nothing real (a
# spawn pointer parked in rbp is always also reachable through the register
# it was copied from) and removes an entire class of false anchor.
STACK_FAMILIES = frozenset({RSP, RBP})

# Registers the Windows x64 ABI lets a callee destroy. After a `call` we must
# assume anything we were tracking in one of these is gone.
VOLATILE_FAMILIES = frozenset(
    REG_FAMILY_BY_NAME[r] for r in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
)


def _reg_family_by_id(md):
    """Map capstone register ids -> family index, built once per disassembler."""
    table = {}
    for reg_id in range(1, 300):
        try:
            name = md.reg_name(reg_id)
        except Exception:
            continue
        fam = REG_FAMILY_BY_NAME.get(name)
        if fam is not None:
            table[reg_id] = fam
    return table


def function_ranges(image):
    """[(start_va, end_va)] from .pdata, restricted to executable sections.

    Returns [] when the image has no usable .pdata; callers fall back to
    whole-section spans.
    """
    section_by_name = getattr(image, "section_by_name", None)
    pdata = section_by_name(".pdata") if section_by_name else None
    if pdata is None:
        return []

    exec_secs = image.exec_sections()
    ranges = set()
    data = pdata.data
    for i in range(len(data) // RUNTIME_FUNCTION_SIZE):
        begin, end, _unwind = struct.unpack_from("<III", data, i * RUNTIME_FUNCTION_SIZE)
        if begin == 0 or end <= begin:
            continue
        start_va = image.image_base + begin
        end_va = image.image_base + end
        for sec in exec_secs:
            # Chained unwind info and a few hand-written stubs produce records
            # that spill past their section; those are not functions we can
            # decode, so drop them rather than clamping into nonsense.
            if sec.contains(start_va) and sec.contains(end_va - 1):
                ranges.add((start_va, end_va))
                break
    return sorted(ranges)


class MemAccess:
    """One `[base + disp]` operand: the unit struct-offset derivation votes on."""

    __slots__ = ("insn", "base_family", "disp", "disp_off", "disp_size", "is_write")

    def __init__(self, insn, base_family, disp, disp_off, disp_size, is_write):
        self.insn = insn
        self.base_family = base_family
        self.disp = disp
        self.disp_off = disp_off
        self.disp_size = disp_size
        self.is_write = is_write

    @property
    def va(self):
        return self.insn.address

    @property
    def text(self):
        return f"{self.insn.mnemonic} {self.insn.op_str}".strip()


class CodeMap:
    """Function list plus on-demand, correctly-aligned disassembly."""

    def __init__(self, image, md=None):
        self.image = image
        self.md = md or make_disassembler()
        self.reg_family = _reg_family_by_id(self.md)
        self.functions = function_ranges(image)
        self.from_pdata = bool(self.functions)
        if not self.functions:
            self.functions = sorted(
                (s.va, s.va + s.virtual_size) for s in image.exec_sections())
        self._sections = {}
        for sec in image.exec_sections():
            self._sections[sec.name] = sec
        # Parallel sorted list of starts, for function_containing()'s bisect
        # and for recognising a tail-call jmp's target as a real function.
        self._starts = [start for start, _end in self.functions]
        self.function_starts = frozenset(self._starts)

    def section_for_va(self, va):
        return self.image.section_for_va(va)

    def function_containing(self, va):
        """(start, end) of the function `va` falls inside, or None."""
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        start, end = self.functions[i]
        return (start, end) if start <= va < end else None

    def instructions(self, start_va, end_va):
        """Decode one function. Not cached: on a real image the full set is
        ~2.2M capstone objects, which is far more memory than the couple of
        seconds of re-decoding it would save.
        """
        sec = self.image.section_for_va(start_va)
        if sec is None:
            return []
        lo = start_va - sec.va
        hi = min(end_va - sec.va, len(sec.data))
        if hi <= lo:
            return []
        return list(self.md.disasm(sec.data[lo:hi], start_va))

    def disasm_window(self, va, before=3, after=4):
        """A few instructions of context around `va`, for a human to read.

        This exists for the case anchoring cannot resolve on its own: when a
        struct field's signatures disagree, the fastest way to find out which
        one is telling the truth is to look at the actual code, the same way
        the manual corrections in known/2026-08-19.json's provenance did by
        hand. Printing it here means that judgment call can be made by
        whoever is running the tool, immediately, instead of by waiting for
        someone else to publish an answer.

        Returns [] if `va` doesn't land inside a function we can decode (no
        .pdata coverage there) or isn't exactly on an instruction boundary.
        """
        rng = self.function_containing(va)
        if rng is None:
            return []
        insns = self.instructions(*rng)
        idx = next((i for i, insn in enumerate(insns) if insn.address == va), None)
        if idx is None:
            return []
        lo, hi = max(0, idx - before), min(len(insns), idx + after + 1)
        return insns[lo:hi]

    def mem_accesses(self, insn):
        """`[base+disp]` operands of `insn` that could be struct field accesses.

        Filtered down to the plain `[reg+disp]` form on purpose:
          * RIP-relative operands are globals, handled by refs.py instead;
          * an index register means an array subscript, where the constant is
            a base offset into the array rather than a member displacement;
          * a segment override is TEB/TLS, never a game struct;
          * rsp/rbp bases are stack frames -- see STACK_FAMILIES;
          * `call [rcx+0x90]` / `jmp [rcx+0x18]` are virtual dispatches, where
            the displacement indexes the vtable rather than naming a data
            member. Measured across the 07/17 -> 08/19/2026 boundary, a
            signature built on one of these was the only GroundItem.YOffset
            fingerprint to vote wrong -- it had latched onto a vtable slot
            that happened to sit at the same offset as the field.
        """
        if insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP):
            return []
        out = []
        ops = insn.operands
        for idx, op in enumerate(ops):
            if op.type != X86_OP_MEM:
                continue
            mem = op.mem
            if mem.base == X86_REG_RIP or mem.base == 0 or mem.index != 0 or mem.segment != 0:
                continue
            fam = self.reg_family.get(mem.base)
            if fam is None or fam in STACK_FAMILIES:
                continue
            out.append(MemAccess(
                insn=insn,
                base_family=fam,
                disp=mem.disp,
                disp_off=insn.encoding.disp_offset,
                disp_size=insn.encoding.disp_size,
                is_write=(idx == 0),
            ))
        return out

    def dest_register_family(self, insn):
        """Family of the register `insn` writes, or None if it writes none."""
        ops = insn.operands
        if not ops or ops[0].type != X86_OP_REG:
            return None
        return self.reg_family.get(ops[0].reg)
