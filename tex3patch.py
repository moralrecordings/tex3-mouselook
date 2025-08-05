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

# converting offsets inside mame
# to_ds = lambda x: hex(x+0x342000)
# from_ds = lambda x: hex(x-0x342000)
# to_cs = lambda x: hex(x+0x35f000)
# from_cs = lambda x: hex(x-0x35f000)

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
add eax,movement_tilt_angle_last
cmp eax,movement_tilt_angle_top
jge check2
mov eax,movement_tilt_angle_top
check2:
cmp eax,movement_tilt_angle_bottom
jle after
mov eax,movement_tilt_angle_bottom
after:
mov movement_tilt_angle, eax
mov movement_tilt_angle_last, eax
ret

[generic]
mov eax, ecx
shl eax, 17
add dword ptr ds:[0x1f2a5], eax
mov eax, edx
shl eax, 1
add eax,dword ptr ds:[0x1f290]
cmp eax,dword ptr ds:[0x1f395]
jge check2
mov eax,dword ptr ds:[0x1f395]
check2:
cmp eax,dword ptr ds:[0x1f391]
jle after
mov eax,dword ptr ds:[0x1f391]
after:
mov dword ptr ds:[0x1f2ad], eax 
mov dword ptr ds:[0x1f290], eax 
ret
"""
MOUSELOOK_CODE = b"\x89\xC8\xC1\xE0\x11\x01\x05\xA5\xF2\x01\x00\x89\xD0\xD1\xE0\x03\x05\x90\xF2\x01\x00\x3B\x05\x95\xF3\x01\x00\x7D\x05\xA1\x95\xF3\x01\x00\x3B\x05\x91\xF3\x01\x00\x7E\x05\xA1\x91\xF3\x01\x00\xA3\xAD\xF2\x01\x00\xA3\x90\xF2\x01\x00\xC3"
MOUSELOOK_OFFSET = CS + 0x364c3

"""
Replace the useless head-turning keyboard controls with code for WASD.
This reuses the original counters for forward and sideways velocity.
Double the speed if shift is held down.

W (keycode 0x11)
A (keycode 0x1e)
S (keycode 0x1f)
D (keycode 0x20)
LShift (keycode 0x2a)

[pseudo]
mov movement_strafe,1

up:
xor eax,eax
test keyboard_state[0x11],3
jz down
sub eax,0x4000

down:
test keyboard_state[0x1f],3
jz leftyrighty
add eax,0x4000

leftyrighty:
test keyboard_state[0x2a],3
jz apply_fwd
shl eax,1
apply_fwd:
mov movement_fwd_veloc_world,eax

left:
xor eax,eax
test keyboard_state[0x1e],3
jz right
sub eax,0xc000

right:
test keyboard_state[0x20],3
jz fin
add eax,0xc000

fin:
test keyboard_state[0x2a],3
jz apply_strafe
shl eax,1
apply_strafe:
mov movement_strafe_veloc_world,eax

and keyboard_state[0x11],1
and keyboard_state[0x1f],1
and keyboard_state[0x1e],1
and keyboard_state[0x20],1
and keyboard_state[0x2a],1


[generic]
mov dword ptr [ds:0x1f35d],1

up:
xor eax,eax
test byte ptr [ds:0x3a1bf+0x11],3
jz down
sub eax,0x4000

down:
test byte ptr [ds:0x3a1bf+0x1f],3
jz leftyrighty
add eax,0x4000

leftyrighty:
test byte ptr [ds:0x3a1bf+0x2a],3
jz apply_fwd
shl eax,1
apply_fwd:
mov dword ptr [ds:0x1f0e1],eax

left:
xor eax,eax
test byte ptr [ds:0x3a1bf+0x1e],3
jz right
sub eax,0xc000

right:
test byte ptr [ds:0x3a1bf+0x20],3
jz fin
add eax,0xc000

fin:
test byte ptr [ds:0x3a1bf+0x2a],3
jz apply_strafe
shl eax,1
apply_strafe:
mov dword ptr [ds:0x1f0dd],eax

and byte ptr [ds:0x3a1bf+0x11],1
and byte ptr [ds:0x3a1bf+0x1f],1
and byte ptr [ds:0x3a1bf+0x1e],1
and byte ptr [ds:0x3a1bf+0x20],1
and byte ptr [ds:0x3a1bf+0x2a],1
"""

WASD_MOD = b"\xC7\x05\x5D\xF3\x01\x00\x01\x00\x00\x00\x31\xC0\xF6\x05\xD0\xA1\x03\x00\x03\x74\x05\x2D\x00\x40\x00\x00\xF6\x05\xDE\xA1\x03\x00\x03\x74\x05\x05\x00\x40\x00\x00\xF6\x05\xE9\xA1\x03\x00\x03\x74\x02\xD1\xE0\xA3\xE1\xF0\x01\x00\x31\xC0\xF6\x05\xDD\xA1\x03\x00\x03\x74\x05\x2D\x00\xC0\x00\x00\xF6\x05\xDF\xA1\x03\x00\x03\x74\x05\x05\x00\xC0\x00\x00\xF6\x05\xE9\xA1\x03\x00\x03\x74\x02\xD1\xE0\xA3\xDD\xF0\x01\x00\x80\x25\xD0\xA1\x03\x00\x01\x80\x25\xDE\xA1\x03\x00\x01\x80\x25\xDD\xA1\x03\x00\x01\x80\x25\xDF\xA1\x03\x00\x01\x80\x25\xE9\xA1\x03\x00\x01"
WASD_OFFSET = CS + 0x3839c
# NOP until the end
WASD_MOD += b"\x90"*(0x3851e - WASD_OFFSET - len(WASD_MOD))


"""
The game engine measures the number of ticks between redraws, and multiplies this delta time value 
by the movement velocity to get the displacement.

For reasons that are unclear, if 0 ticks have elapsed, the engine rounds this up to 4.
Which means e.g. in areas of low geometry, Tex will start rocketing around far too quickly.
This happens in the original movement code as well, adding to the difficulty of the controls.
Fix this by nopping out that section of code.

nop
nop
nop
nop
nop
nop
nop

"""


DT_MOD = b"\x90\x90\x90\x90\x90\x90\x90"
DT_OFFSET = 0x36460


"""
The game normally maps "run" to the R key, but we're using it now, so nop out that code.
"""

RKEY_MOD = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
RKEY_OFFSET = 0x38631

"""
The original control scheme has LCtrl/LAlt to drop eye level, LShift to raise eye level, and 
E to restore to normal eye level. Let's simplify this to crouching while holding C, or reach up on tippytoes while holding R, else restore
to normal eye level.

C (keycode 0x2e)
R (keycode 0x13)

[pseudo]
test keyboard_state[0x2e],3
jnz crouch 
test keyboard_state[0x13],3
jz restore

tippytoes:
mov eax,movement_eye_level_incr
add movement_eye_level,eax
mov eax,movement_eye_level
cmp eax,movement_eye_level_max
jle fin
mov eax, movement_eye_level_max
mov movement_eye_level,eax
jmp fin

crouch:
mov eax,movement_eye_level_incr
sub movement_eye_level,eax
mov eax,movement_eye_level
cmp eax,movement_eye_level_min
jge fin
mov eax, movement_eye_level_min
mov movement_eye_level,eax
jmp fin


; if incr > abs(eye level - neutral), eye level = neutral, end
restore:
mov ebx,movement_eye_level_min
add ebx,movement_eye_level_restore
mov eax,movement_eye_level
sub eax,ebx
push edx
cdq
xor eax, edx
sub eax, edx
pop edx
cmp eax,movement_eye_level_incr
jle skip

; if eye level > neutral, incr is negative, else positive
mov ebx,movement_eye_level_min
add ebx,movement_eye_level_restore
mov eax,movement_eye_level_incr
cmp ebx,movement_eye_level
jg adjust
neg eax

; eye level += incr
adjust:
add movement_eye_level,eax
jmp fin

skip:
mov ebx,movement_eye_level_min
add ebx,movement_eye_level_restore
mov movement_eye_level,ebx

fin:
and keyboard_state[0x2e],1
and keyboard_state[0x13],1

ret



[generic]
test byte ptr [ds:0x3a1bf+0x2e],3
jnz crouch
test byte ptr [ds:0x3a1bf+0x13],3
jz restore 

tippytoes:
mov eax,dword ptr [ds:0x1f365]
add dword ptr [ds:0x1f260],eax
mov eax,dword ptr [ds:0x1f260]
cmp eax,dword ptr [ds:0x1f385]
jle fin
mov eax, dword ptr [ds:0x1f385]
mov dword ptr [ds:0x1f260],eax
jmp fin


crouch:
mov eax,dword ptr [ds:0x1f365]
sub dword ptr [ds:0x1f260],eax
mov eax,dword ptr [ds:0x1f260]
cmp eax,dword ptr [ds:0x1f389]
jge fin
mov eax, dword ptr [ds:0x1f389]
mov dword ptr [ds:0x1f260],eax
jmp fin

restore:
mov ebx,dword ptr [ds:0x1f389]
add ebx,dword ptr [ds:0x1f264]
mov eax,dword ptr [ds:0x1f260]
sub eax,ebx
push edx
cdq
xor eax, edx
sub eax, edx 
pop edx
cmp eax,dword ptr [ds:0x1f365]
jle skip

mov ebx,dword ptr [ds:0x1f389]
add ebx,dword ptr [ds:0x1f264]
mov eax,dword ptr [ds:0x1f365]
cmp ebx,dword ptr [ds:0x1f260]
jg adjust
neg eax

adjust:
add dword ptr [ds:0x1f260],eax
jmp fin

skip:
mov ebx,dword ptr [ds:0x1f389]
add ebx,dword ptr [ds:0x1f264]
mov dword ptr [ds:0x1f260],ebx

fin:
and byte ptr [ds:0x3a1bf+0x2e],1
and byte ptr [ds:0x3a1bf+0x13],1
ret

"""
CROUCH_MOD = b"\xF6\x05\xED\xA1\x03\x00\x03\x75\x31\xF6\x05\xD2\xA1\x03\x00\x03\x74\x4C\xA1\x65\xF3\x01\x00\x01\x05\x60\xF2\x01\x00\xA1\x60\xF2\x01\x00\x3B\x05\x85\xF3\x01\x00\x0F\x8E\x87\x00\x00\x00\xA1\x85\xF3\x01\x00\xA3\x60\xF2\x01\x00\xEB\x7B\xA1\x65\xF3\x01\x00\x29\x05\x60\xF2\x01\x00\xA1\x60\xF2\x01\x00\x3B\x05\x89\xF3\x01\x00\x7D\x63\xA1\x89\xF3\x01\x00\xA3\x60\xF2\x01\x00\xEB\x57\x8B\x1D\x89\xF3\x01\x00\x03\x1D\x64\xF2\x01\x00\xA1\x60\xF2\x01\x00\x29\xD8\x52\x99\x31\xD0\x29\xD0\x5A\x3B\x05\x65\xF3\x01\x00\x7E\x23\x8B\x1D\x89\xF3\x01\x00\x03\x1D\x64\xF2\x01\x00\xA1\x65\xF3\x01\x00\x3B\x1D\x60\xF2\x01\x00\x7F\x02\xF7\xD8\x01\x05\x60\xF2\x01\x00\xEB\x12\x8B\x1D\x89\xF3\x01\x00\x03\x1D\x64\xF2\x01\x00\x89\x1D\x60\xF2\x01\x00\x80\x25\xED\xA1\x03\x00\x01\x80\x25\xD2\xA1\x03\x00\x01\xC3"
CROUCH_OFFSET = 0x380ae


CREDIT_MOD = b"(c) 1993.        \rMouselook v1.0 (c) 2025 moralrecordings.    \r                                "
CREDIT_OFFSET = DS + 0x1c18d

CODE_PATCHES = [
    (MOUSELOOK_CODE, MOUSELOOK_OFFSET),
    (WASD_MOD, WASD_OFFSET),
    (DT_MOD, DT_OFFSET),
    (RKEY_MOD, RKEY_OFFSET),
    (CROUCH_MOD, CROUCH_OFFSET),
]

DATA_PATCHES = [
    (CREDIT_MOD, CREDIT_OFFSET)
]


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


for mod_code, mod_offset in CODE_PATCHES:
    print("Fixups to remove:")
    PATCH_RANGE = (mod_offset, mod_offset + len(mod_code))
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
    decoder = iced_x86.Decoder(32, mod_code)
    for instr in decoder:
        print((instr, instr.code))
        offset = mod_offset + instr.ip
        code = instr.code
        srcoff = offset % le_header.page_size
        page = offset // le_header.page_size
        # this is incomplete, there's hundreds of instructions in x86 which access memory.
        # I'm just adding them when I need them 
        match code:
            case (iced_x86.Code.ADD_RM32_R32 | 
                  iced_x86.Code.MOV_RM32_IMM32 | 
                  iced_x86.Code.AND_R8_RM8 |
                  iced_x86.Code.TEST_RM8_IMM8 |
                  iced_x86.Code.CMP_R32_RM32 |
                  iced_x86.Code.MOV_R32_RM32 |
                  iced_x86.Code.ADD_R32_RM32 |
                  iced_x86.Code.AND_RM8_IMM8):
                fixup = FixupTuple("fix_32off_32", 0x7, 0x10, DATA_OBJ, srcoff+2, utils.from_uint32_le(mod_code[instr.ip+2:instr.ip+6]))
                print((page, None, hex(offset), fixup))
                fixup_records[page].append(fixup)
            case (iced_x86.Code.MOV_RM32_R32 |
                  iced_x86.Code.SUB_RM32_R32):
                # this bastard can have both memory and registers as a source operand
                if instr.memory_displacement:
                    fixup = FixupTuple("fix_32off_32", 0x7, 0x10, DATA_OBJ, srcoff+2, utils.from_uint32_le(mod_code[instr.ip+2:instr.ip+6]))
                    print((page, None, hex(offset), fixup))
                    fixup_records[page].append(fixup)
            case (iced_x86.Code.MOV_AL_MOFFS8 |
                  iced_x86.Code.MOV_MOFFS32_EAX |
                  iced_x86.Code.MOV_EAX_MOFFS32):
                fixup = FixupTuple("fix_32off_32", 0x7, 0x10, DATA_OBJ, srcoff+1, utils.from_uint32_le(mod_code[instr.ip+1:instr.ip+5]))
                print((page, None, hex(offset), fixup))
                fixup_records[page].append(fixup)
            case (iced_x86.Code.JMP_RM32):
                fixup = FixupTuple("fix_32off_32", 0x7, 0x10, CODE_OBJ, srcoff+3, utils.from_uint32_le(mod_code[instr.ip+3:instr.ip+7]))
                print((page, None, hex(offset), fixup))
                fixup_records[page].append(fixup)


    page_data[mod_offset:mod_offset+len(mod_code)] = mod_code

for mod_data, mod_offset in DATA_PATCHES:
    page_data[mod_offset:mod_offset+len(mod_data)] = mod_data

with open("TEX3MOD.EXE", "wb") as out:
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
