"""Find the instructions that reference a known global address.

This is the bootstrap step. You already know that (say) CharInfo lives at
0x140eb1d08 in the current build, because someone published that number.
What you do NOT have is a way to find it again next patch. So we work
backwards: locate every instruction in the current binary that references
that address, because those instructions are what stay recognisable across
patches even when the address itself moves.

On x64, globals are almost always reached RIP-relative:

    48 8B 05 <disp32>        mov rax, [rip + disp32]

and the CPU computes the effective address from the address of the *next*
instruction, not the current one:

    target = insn_va + insn_len + disp32

Getting that "+ insn_len" wrong is the single most common way to produce a
tool that silently emits addresses that are off by a few bytes.

Search strategy is two-stage:

  Stage A -- a fast arithmetic filter over the raw bytes, using numpy.
             Rearranging the equation above gives, for a candidate disp32
             sitting at byte offset p within a section:

                 disp32 + p == target - section_va - 4 - trailing

             where `trailing` is however many bytes follow the disp32 inside
             the same instruction (0 for the common forms, 1/2/4 when an
             immediate follows, e.g. `mov dword [rip+d], imm32`). We test
             each plausible `trailing` value.

  Stage B -- decode with capstone to confirm the hit is a real instruction
             whose RIP-relative operand genuinely resolves to the target.
             Stage A is deliberately loose and will produce false positives;
             stage B is what makes the result trustworthy.
"""

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

# Bytes that may follow a disp32 inside the same instruction.
TRAILING_SIZES = (0, 1, 2, 4)

# How far back from the disp32 an instruction may start.
MAX_INSN_PREFIX = 15


def make_disassembler():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


class RefSite:
    """One instruction that references a target global."""

    __slots__ = ("va", "size", "bytes", "disp_off", "section", "text", "target")

    def __init__(self, va, size, raw, disp_off, section, text, target):
        self.va = va
        self.size = size
        self.bytes = raw
        self.disp_off = disp_off
        self.section = section
        self.text = text
        self.target = target

    def __repr__(self):
        return f"<RefSite 0x{self.va:X} {self.text} disp_off={self.disp_off}>"


def rip_target(insn):
    """Resolved absolute VA of an instruction's RIP-relative operand, or None."""
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return insn.address + insn.size + op.mem.disp
    return None


def _stage_a_candidates(data, section_va, target):
    """Byte offsets where a disp32 *might* encode a reference to `target`."""
    n = len(data) - 4
    if n <= 0:
        return np.empty(0, dtype=np.int64)

    a = np.frombuffer(data, dtype=np.uint8)
    disp = (
        a[0:n].astype(np.uint32)
        | (a[1:n + 1].astype(np.uint32) << 8)
        | (a[2:n + 2].astype(np.uint32) << 16)
        | (a[3:n + 3].astype(np.uint32) << 24)
    ).astype(np.int64)
    # Reinterpret as signed 32-bit.
    disp[disp >= 0x80000000] -= 0x100000000

    lhs = disp + np.arange(n, dtype=np.int64)

    hits = []
    for trailing in TRAILING_SIZES:
        c = target - section_va - 4 - trailing
        hits.append(np.nonzero(lhs == c)[0])
    if not hits:
        return np.empty(0, dtype=np.int64)
    return np.unique(np.concatenate(hits))


def find_refs(image, target, md=None, sections=None, max_sites=None):
    """Return validated RefSite objects referencing `target`."""
    md = md or make_disassembler()
    sections = sections if sections is not None else image.exec_sections()
    found = {}

    for sec in sections:
        data = sec.data
        for p in _stage_a_candidates(data, sec.va, target):
            p = int(p)
            lo = max(0, p - MAX_INSN_PREFIX)
            for s in range(p - 2, lo - 1, -1):
                chunk = data[s:s + 16]
                if len(chunk) < 4:
                    continue
                insn = next(md.disasm(chunk, sec.va + s, count=1), None)
                if insn is None:
                    continue
                # The disp32 must lie inside this instruction, at the offset
                # capstone reports, and the operand must resolve to our target.
                if insn.encoding.disp_size != 4:
                    continue
                if insn.encoding.disp_offset != p - s:
                    continue
                if s + insn.size <= p + 3:
                    continue
                if rip_target(insn) != target:
                    continue
                site = RefSite(
                    va=insn.address,
                    size=insn.size,
                    raw=bytes(insn.bytes),
                    disp_off=insn.encoding.disp_offset,
                    section=sec.name,
                    text=f"{insn.mnemonic} {insn.op_str}".strip(),
                    target=target,
                )
                found[site.va] = site
                break
            if max_sites and len(found) >= max_sites:
                break

    return sorted(found.values(), key=lambda r: r.va)
