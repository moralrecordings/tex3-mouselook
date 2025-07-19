#!/usr/bin/env python3

from typing import NamedTuple

import iced_x86

from mrcrowbar import utils
from mrcrowbar import models as mrc

class LEHeader(mrc.Block):
    magic = mrc.Const(mrc.Bytes(length=2), b'LE')
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
    res_table_offset =mrc.UInt32_LE()
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
    per_page_csum_offset =mrc.UInt32_LE()
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
        header = exe[ptr:ptr+64]
        if header[0:2] in (b'MZ', b'BW'):
            relocation_table_offset = utils.from_uint16_le(header[0x18:0x1a])
            if relocation_table_offset == 0x40:
                code32_start = utils.from_uint16_le(header[0x3c:0x3e])
                if code32_start != 0:
                    print("Found LE inside!")
                    return (ptr, ptr+code32_start)
            page_count = utils.from_uint16_le(header[0x4:0x6])
            last_page_bytes = utils.from_uint16_le(header[0x2:0x4])
            total_size = (page_count << 9) + last_page_bytes
            if header[0:2] == b'MZ':
                total_size -= 0x200
            result.append((header[0:2], exe[ptr:ptr+total_size]))
            ptr += total_size
        else:
            raise RuntimeError(f'I give up {header[0:2]}')
           
    raise RuntimeError("Couldn't find LE!")

class FixupTuple(NamedTuple):
    id: str
    src: int
    flags: int
    objnum: int
    srcoff: int
    data: int|None

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
        flags = buffer[fix_ptr+1]
        srcoff = utils.from_uint16_le(buffer[fix_ptr+2:fix_ptr+4])
        objnum = buffer[fix_ptr+4] - 1
        fix_ptr += 5
        if src == 0x7:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr:fix_ptr+4])
                fix_ptr += 4
                items.append(FixupTuple("fix_32off_32", src, flags, objnum, srcoff, fix_data))
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr:fix_ptr+2])
                fix_ptr += 2
                items.append(FixupTuple("fix_32off_16", src, flags, objnum, srcoff, fix_data))
        elif src == 0x5:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr:fix_ptr+4])
                fix_ptr += 4
                items.append(FixupTuple("fix_16off_32", src, flags, objnum, srcoff, fix_data))
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr:fix_ptr+2])
                fix_ptr += 2
                items.append(FixupTuple("fix_16off_16", src, flags, objnum, srcoff, fix_data))
        elif src == 0x6:
            if flags & 0x10:
                fix_data = utils.from_uint32_le(buffer[fix_ptr:fix_ptr+4])
                fix_ptr += 4
                items.append(FixupTuple("fix_1632ptr_32", src, flags, objnum, srcoff, fix_data))
            else:
                fix_data = utils.from_uint16_le(buffer[fix_ptr:fix_ptr+2])
                fix_ptr += 2
                items.append(FixupTuple("fix_1632ptr_16", src, flags, objnum, srcoff, fix_data))
        elif src == 0x2:
            items.append(FixupTuple("fix_16sel", src, flags, objnum, srcoff, None))
        else:
            raise RuntimeError(f"failed to decode at 0x{ptr_start:08x}! {src} {flags}")
    return items

CS = 0x0
DS = 0x52000

CODE_OBJ = 0
DATA_OBJ = 2

"""
The game keeps track of the mouse in two ways; as a clamped (x, y) position in screen coordinates,
and as a signed 16-bit x, y position that wraps and is unbound. The function we're patching has
delta values based on the unbound x, y position loaded into ecx and edx. 
Normally it uses these to change two variables that track the player's turning and forward velocity;
we want to ignore those and instead mod the variables that track the player's rotation and head tilt.

Movement tilt ranges from -0x384 (ceiling) to 0x384 (floor)
Movement rotation ranges from 0 to ~0xd000000

Inject at 0x364c3:

[pseudo]
mov eax, ecx
shl eax, 17
add movement_rot_angle, eax
mov eax, edx
shl eax, 1
add movement_tilt_angle, eax
add movement_tilt_angle_last, eax
ret

[generic]
mov eax, ecx
shl eax, 17
add ds:[0x1f2a5], eax
mov eax, edx
shl eax, 1
add ds:[0x1f2ad], eax 
add ds:[0x1f290], eax 
ret
"""
MOUSELOOK_CODE = b"\x89\xC8\xC1\xE0\x11\x01\x05\xA5\xF2\x01\x00\x89\xD0\xD1\xE0\x01\x05\xAD\xF2\x01\x00\x01\x05\x90\xF2\x01\x00\xC3"
MOUSELOOK_OFFSET = CS + 0x364c3


CREDIT_MOD = b"(c) 1993.        \rMouselook v0.9 (c) 2025 moralrecordings.    \r                                "
CREDIT_OFFSET = DS + 0x1c18d


f = open('TEX3.EXE', 'rb').read()
mz_off, le_off = search_for_le(f)
le_header = LEHeader(f[le_off:])

# loader_section, fixup_section, data_section, debug_section

fixup_page_table = FixupPageTable(f[le_off+le_header.fixup_page_table_offset:][:4*(le_header.module_num_pages + 1)])
fixup_record_table = []
for i in range(le_header.module_num_pages):
    fixup_record_table.append(f[le_off + le_header.fixup_record_table_offset:][fixup_page_table.offsets[i]:fixup_page_table.offsets[i+1]])

fixup_records = [fixups_decode(x) for x in fixup_record_table]
object_table = ObjectTable(f[le_off + le_header.obj_table_offset:][:le_header.obj_count*0x18])
object_page_table = ObjectPageTable(f[le_off + le_header.obj_page_table_offset:][:le_header.module_num_pages*0x4])
   
page_data_orig = f[mz_off + le_header.data_pages_offset:]
page_data = bytearray(page_data_orig)

iff = iced_x86.InstructionInfoFactory()

PATCH_RANGE = (MOUSELOOK_OFFSET, MOUSELOOK_OFFSET + len(MOUSELOOK_CODE))

print("Fixups to remove:")
for i in range(len(fixup_records)):
    page_offset = i*le_header.page_size
    if page_offset >= PATCH_RANGE[1] or (page_offset + le_header.page_size) < PATCH_RANGE[0]:
        continue
    to_remove = []
    for j, record in enumerate(fixup_records[i]):
        src_addr = (record.srcoff + page_offset)
        if src_addr in range(PATCH_RANGE[0], PATCH_RANGE[1]):
            print((i, j, hex(src_addr), record))
            to_remove.append(j)
    to_remove.reverse()
    for j in to_remove:
        fixup_records[i].pop(j)
print("Fixups to add:")
for mod_code, mod_offset in [(MOUSELOOK_CODE, MOUSELOOK_OFFSET)]:
    decoder = iced_x86.Decoder(32, mod_code)
    for instr in decoder:
        print(instr)
        offset = mod_offset + instr.ip
        code = instr.code
        srcoff = offset % le_header.page_size
        page = offset // le_header.page_size
        # this is incomplete, there's god knows how many instructions in x86 which access memory.
        # I'm just adding them when I need them 
        if code == iced_x86.Code.ADD_RM32_R32:
            fixup = FixupTuple("fix_32off_32", 0x7, 0x10, DATA_OBJ, srcoff+2, utils.from_uint32_le(mod_code[instr.ip+2:instr.ip+6]))
            print((page, None, hex(offset), fixup))
            fixup_records[page].append(fixup)

    page_data[mod_offset:mod_offset+len(mod_code)] = mod_code

for mod_data, mod_offset in [(CREDIT_MOD, CREDIT_OFFSET)]:
    page_data[mod_offset:mod_offset+len(mod_data)] = mod_data

with open("TEXMOD.EXE", "wb") as out:
    fixup_output = [fixups_encode(x) for x in fixup_records]
    fixup_page_table.offsets = []
    acc = 0
    for x in fixup_output:
        fixup_page_table.offsets.append(acc)
        acc += len(x)
    fixup_page_table.offsets.append(acc)
    fixup_page_table_output = fixup_page_table.export_data()
    fixup_record_table_output = b''.join(fixup_output)

    post_fixup_start = le_header.import_module_table_offset
    post_fixup_end = mz_off + le_header.data_pages_offset - le_off
    post_fixup_blob = f[le_off + post_fixup_start: le_off+post_fixup_end]

    le_header.fixup_record_table_offset = le_header.fixup_page_table_offset + len(fixup_page_table_output)
    le_header.fixup_section_size = len(fixup_page_table_output) + len(fixup_record_table_output)
    le_header.fixup_section_csum = 0

    le_header.import_module_table_offset = le_header.fixup_page_table_offset + le_header.fixup_section_size
    le_header.import_proc_table_offset = le_header.import_module_table_offset
    le_header.data_pages_offset = le_off + le_header.import_module_table_offset + len(post_fixup_blob) - mz_off

    out.write(f[:le_off])
    out.write(le_header.export_data())
    header_size = le_header.get_size()
    out.write(f[le_off+header_size:le_off+le_header.fixup_page_table_offset])
    out.write(fixup_page_table_output)
    out.write(fixup_record_table_output)
    out.write(post_fixup_blob)
    out.write(page_data)
