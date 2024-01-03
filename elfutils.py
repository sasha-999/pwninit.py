import os
import struct


def is_elf(path):
    if not os.path.isfile(path):
        return False
    with open(path, "rb") as f:
        return f.read(4) == b"\x7fELF"


def get_debug_link(elf):
    sect = elf.get_section_by_name(".gnu_debuglink")
    if sect is None:
        return None
    data = sect.data()
    i = data.find(b"\x00")
    debug_link = data[:i].decode()
    crc32 = struct.unpack("<I", data[-4:])[0]
    return debug_link, crc32


def vaddr_to_offset(elf, vaddr):
    for segment in elf.iter_segments():
        offset = vaddr - segment.header["p_vaddr"]
        if 0 <= offset < segment.header["p_memsz"]:
            return segment.header["p_offset"] + offset
    return None


def get_segments(elf, p_type):
    segments = []
    for segment in elf.iter_segments():
        if segment.header["p_type"] == p_type:
            segments.append(segment)
    return segments


def get_segment(elf, p_type):
    segments = get_segments(elf, p_type)
    if segments:
        return segments[0]
    return None


def get_interp_patch(elf):
    interp = get_segment(elf, "PT_INTERP")
    if interp:
        return interp.get_interp_name(), interp.header["p_offset"]
    return None


def get_dynamic(elf):
    return get_segment(elf, "PT_DYNAMIC")


def get_needed_patches(elf):
    dynamic = get_dynamic(elf)
    if dynamic is None:
        return []
    needed = []
    strtab = None
    for tag in dynamic.iter_tags():
        type = tag.entry["d_tag"]
        if type == "DT_NEEDED":
            needed.append((tag.needed, tag.entry["d_val"]))
        elif type == "DT_STRTAB":
            strtab = vaddr_to_offset(elf, tag.entry["d_ptr"])
    for i, (name, off) in enumerate(needed):
        needed[i] = (name, strtab+off)
    return needed


def get_interp(elf):
    interp = get_interp_patch(elf)
    if interp is None:
        return None
    return interp[0]


def get_needed(elf):
    return list(name for name, off in get_needed_patches(elf))


def get_arch(elf):
    return {
        "EM_X86_64": "amd64",
        "EM_386": "i386",
    }.get(elf["e_machine"], None)
