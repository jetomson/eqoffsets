"""Thin wrapper over pefile giving us the few things we actually need:
section bytes, VA<->offset math, and 'which section does this VA live in'.

All addresses in this project are *preferred-base virtual addresses*, i.e.
image_base + rva, with image_base taken from the PE optional header
(0x140000000 for eqgame.exe). Published MySEQ offset lists use this same
convention -- that is why they look like 0x140eb78f4.
"""

import pefile

IMAGE_SCN_MEM_EXECUTE = 0x20000000


class Section:
    __slots__ = ("name", "rva", "va", "virtual_size", "data", "executable")

    def __init__(self, name, rva, va, virtual_size, data, executable):
        self.name = name
        self.rva = rva
        self.va = va
        self.virtual_size = virtual_size
        self.data = data
        self.executable = executable

    @property
    def va_end(self):
        return self.va + self.virtual_size

    def contains(self, va):
        return self.va <= va < self.va_end

    def __repr__(self):
        return f"<Section {self.name} va=0x{self.va:X} size=0x{self.virtual_size:X}>"


class PEImage:
    def __init__(self, path):
        self.path = str(path)
        pe = pefile.PE(self.path, fast_load=True)
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        self.machine = pe.FILE_HEADER.Machine
        self.sections = []

        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
            raw = s.get_data()
            vsize = s.Misc_VirtualSize or len(raw)
            # Raw data is padded up to FileAlignment. Trim to the virtual size so
            # we never match against padding that does not exist at runtime.
            data = raw[:vsize]
            if len(data) < vsize:
                data = data + b"\x00" * (vsize - len(data))
            self.sections.append(
                Section(
                    name=name,
                    rva=s.VirtualAddress,
                    va=self.image_base + s.VirtualAddress,
                    virtual_size=vsize,
                    data=data,
                    executable=bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                )
            )
        pe.close()

    @property
    def is_x64(self):
        return self.machine == 0x8664

    def exec_sections(self):
        return [s for s in self.sections if s.executable]

    def section_by_name(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_for_va(self, va):
        for s in self.sections:
            if s.contains(va):
                return s
        return None

    def in_image(self, va):
        return self.image_base <= va < self.image_base + self.size_of_image

    def read_va(self, va, length):
        s = self.section_for_va(va)
        if s is None:
            return None
        off = va - s.va
        return s.data[off:off + length]

    def cstring_at(self, va, maxlen=96):
        """Return a printable ASCII C string at va, or None."""
        raw = self.read_va(va, maxlen)
        if not raw:
            return None
        end = raw.find(b"\x00")
        if end <= 3:
            return None
        text = raw[:end]
        if not all(32 <= c < 127 for c in text):
            return None
        return text.decode("ascii")

    def __repr__(self):
        return f"<PEImage {self.path} base=0x{self.image_base:X} sections={len(self.sections)}>"
