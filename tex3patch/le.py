from __future__ import annotations

from typing import NamedTuple

from mrcrowbar import models as mrc
from mrcrowbar import utils


class LEHeader(mrc.Block):
    magic = mrc.Const(mrc.Bytes(length=2), b"LE")
    b_ord = mrc.UInt8()
    w_ord = mrc.UInt8()
    format_level = mrc.UInt32_LE()
    cpu_type = mrc.UInt16_LE()
    os_type = mrc.UInt16_LE()
    module_version = mrc.UInt32_LE()
    module_flags = mrc.UInt32_LE()
    module_num_pages = mrc.UInt32_LE()
    eip_obj_num = mrc.UInt32_LE()
    eip = mrc.UInt32_LE()
    esp_obj_num = mrc.UInt32_LE()
    esp = mrc.UInt32_LE()
    page_size = mrc.UInt32_LE()
    page_offset_shift = mrc.UInt32_LE()
    fixup_section_size = mrc.UInt32_LE()
    fixup_section_csum = mrc.UInt32_LE()
    loader_section_size = mrc.UInt32_LE()
    loader_section_csum = mrc.UInt32_LE()
    obj_table_offset = mrc.UInt32_LE()
    obj_count = mrc.UInt32_LE()
    obj_page_table_offset = mrc.UInt32_LE()
    obj_iter_pages_offset = mrc.UInt32_LE()
    res_table_offset = mrc.UInt32_LE()
    res_count = mrc.UInt32_LE()
    resident_name_table_offset = mrc.UInt32_LE()
    entry_table_offset = mrc.UInt32_LE()
    module_directives_offset = mrc.UInt32_LE()
    module_directives_count = mrc.UInt32_LE()
    fixup_page_table_offset = mrc.UInt32_LE()
    fixup_record_table_offset = mrc.UInt32_LE()
    import_module_table_offset = mrc.UInt32_LE()
    import_module_count = mrc.UInt32_LE()
    import_proc_table_offset = mrc.UInt32_LE()
    per_page_csum_offset = mrc.UInt32_LE()
    data_pages_offset = mrc.UInt32_LE()
    preload_pages_count = mrc.UInt32_LE()
    nonres_name_table_offset = mrc.UInt32_LE()
    nonres_name_table_length = mrc.UInt32_LE()
    nonres_name_table_csum = mrc.UInt32_LE()
    auto_ds_object_count = mrc.UInt32_LE()
    debug_info_offset = mrc.UInt32_LE()
    debug_info_length = mrc.UInt32_LE()
    instance_preload_count = mrc.UInt32_LE()
    instance_demand_count = mrc.UInt32_LE()
    heap_size = mrc.UInt32_LE()
    stack_size = mrc.UInt32_LE()


class FixupPageTable(mrc.Block):
    offsets = mrc.UInt32_LE(stream=True)


class ObjectTableEntry(mrc.Block):
    virtual_size = mrc.UInt32_LE()
    reloc_base_addr = mrc.UInt32_LE()
    object_flags = mrc.UInt16_LE()
    unused1 = mrc.UInt16_LE()
    page_table_index = mrc.UInt32_LE()
    page_table_entries = mrc.UInt32_LE()
    unused2 = mrc.UInt32_LE()


class ObjectTable(mrc.Block):
    entries = mrc.BlockField(ObjectTableEntry, stream=True)


# this looks very different to the definition in the IBM document
# doesn't matter, this is what DOS/32A does
class ObjectPageTableEntry(mrc.Block):
    unk = mrc.UInt16_LE()
    value = mrc.UInt16_LE()


class ObjectPageTable(mrc.Block):
    entries = mrc.BlockField(ObjectPageTableEntry, stream=True)


def search_for_le(exe: bytes) -> tuple[int, int]:
    ptr = 0
    result = []
    while ptr < len(exe):
        header = exe[ptr : ptr + 64]
        if header[0:2] in (b"MZ", b"BW"):
            relocation_table_offset = utils.from_uint16_le(header[0x18:0x1A])
            if relocation_table_offset == 0x40:
                code32_start = utils.from_uint16_le(header[0x3C:0x3E])
                if code32_start != 0:
                    print("Found LE inside!")
                    return (ptr, ptr + code32_start)
            page_count = utils.from_uint16_le(header[0x4:0x6])
            last_page_bytes = utils.from_uint16_le(header[0x2:0x4])
            total_size = (page_count << 9) + last_page_bytes
            if header[0:2] == b"MZ":
                total_size -= 0x200
            result.append((header[0:2], exe[ptr : ptr + total_size]))
            ptr += total_size
        else:
            raise RuntimeError(f"I give up {header[0:2]}")

    raise RuntimeError("Couldn't find LE!")


class FixupTuple(NamedTuple):
    id: str
    src: int
    flags: int
    objnum: int
    srcoff: int
    data: int | None


def fixups_encode(fixups: list[FixupTuple]) -> bytes:
    buffer = bytearray()
    for id, src, flags, objnum, srcoff, fix_data in fixups:
        buffer.append(src)
        buffer.append(flags)
        buffer.extend(utils.to_uint16_le(srcoff))
        buffer.append(objnum + 1)
        if id in ("fix_32off_16", "fix_16off_16", "fix_1632ptr_16"):
            buffer.extend(utils.to_uint16_le(fix_data))
        elif id in ("fix_32off_32", "fix_16off_32", "fix_1632ptr_32"):
            buffer.extend(utils.to_uint32_le(fix_data))
        elif id == "fix_16sel":
            pass
        else:
            raise RuntimeError(f"failed to encode fixup type {id}!")
    return bytes(buffer)


def fixups_decode(buffer: bytes) -> list[FixupTuple]:
    fix_ptr = 0
    items: list[FixupTuple] = []
    while fix_ptr < len(buffer):
        ptr_start = fix_ptr
        src = buffer[fix_ptr]
        flags = buffer[fix_ptr + 1]
        srcoff = utils.from_uint16_le(buffer[fix_ptr + 2 : fix_ptr + 4])
        objnum = buffer[fix_ptr + 4] - 1
        fix_ptr += 5
        if src == 0x7:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr : fix_ptr + 4])
                fix_ptr += 4
                items.append(
                    FixupTuple("fix_32off_32", src, flags, objnum, srcoff, fix_data)
                )
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr : fix_ptr + 2])
                fix_ptr += 2
                items.append(
                    FixupTuple("fix_32off_16", src, flags, objnum, srcoff, fix_data)
                )
        elif src == 0x5:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr : fix_ptr + 4])
                fix_ptr += 4
                items.append(
                    FixupTuple("fix_16off_32", src, flags, objnum, srcoff, fix_data)
                )
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr : fix_ptr + 2])
                fix_ptr += 2
                items.append(
                    FixupTuple("fix_16off_16", src, flags, objnum, srcoff, fix_data)
                )
        elif src == 0x6:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr : fix_ptr + 4])
                fix_ptr += 4
                items.append(
                    FixupTuple("fix_1632ptr_32", src, flags, objnum, srcoff, fix_data)
                )
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr : fix_ptr + 2])
                fix_ptr += 2
                items.append(
                    FixupTuple("fix_1632ptr_16", src, flags, objnum, srcoff, fix_data)
                )
        elif src == 0x2:
            items.append(FixupTuple("fix_16sel", src, flags, objnum, srcoff, None))
        else:
            raise RuntimeError(f"failed to decode at 0x{ptr_start:08x}! {src} {flags}")
    return items
