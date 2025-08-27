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
        magic = header[0:2]
        if magic in (b'MZ', b'BW'):
            relocation_table_offset = utils.from_uint16_le(header[0x18:0x1a])
            if relocation_table_offset == 0x40:
                code32_start = utils.from_uint16_le(header[0x3c:0x3e])
                if code32_start != 0:
                    print(f"Found {magic} at 0x{ptr:08x}")
                    print(f"Found LE at 0x{ptr+code32_start:08x}")
                    return (ptr, ptr+code32_start)
            page_count = utils.from_uint16_le(header[0x4:0x6])
            last_page_bytes = utils.from_uint16_le(header[0x2:0x4])
            total_size = (page_count << 9) + last_page_bytes
            if magic == b'MZ':
                total_size -= 0x200
            print(f"Found {magic} at 0x{ptr:08x}, size 0x{total_size:08x}, end offset 0x{ptr+total_size:08x}")
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
# to_ds = lambda x: hex(x+0x398000)
# from_ds = lambda x: hex(x-0x398000)
# to_cs = lambda x: hex(x+0x3b7000)
# from_cs = lambda x: hex(x-0x3b7000)

"""
The game keeps track of the mouse in two ways; as a clamped (x, y) position in screen coordinates,
and as a signed 16-bit x, y position that wraps and is unbound. The function we're patching has
delta values based on the unbound x, y position loaded into ecx and edx. 
Normally it uses these to change two variables that track the player's turning and forward velocity;
we want to ignore those and instead mod the variables that track the player's rotation and head tilt.

Movement tilt ranges from -0x384 (ceiling) to 0x384 (floor)
Movement rotation ranges from 0 to ~0xd000000

Inject at 0x59b3f:

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
add dword ptr ds:[0x315fd], eax
mov eax, edx
shl eax, 1
add eax,dword ptr ds:[0x315e8]
cmp eax,dword ptr ds:[0x316f1]
jge check2
mov eax,dword ptr ds:[0x316f1]
check2:
cmp eax,dword ptr ds:[0x316ed]
jle after
mov eax,dword ptr ds:[0x316ed]
after:
mov dword ptr ds:[0x31605], eax 
mov dword ptr ds:[0x315e8], eax 
ret
"""
MOUSELOOK_CODE = b"\x89\xC8\xC1\xE0\x11\x01\x05\xFD\x15\x03\x00\x89\xD0\xD1\xE0\x03\x05\xE8\x15\x03\x00\x3B\x05\xF1\x16\x03\x00\x7D\x05\xA1\xF1\x16\x03\x00\x3B\x05\xED\x16\x03\x00\x7E\x05\xA1\xED\x16\x03\x00\xA3\x05\x16\x03\x00\xA3\xE8\x15\x03\x00\xC3"
MOUSELOOK_OFFSET = CS + 0x59b73

"""
Replace the useless head-turning keyboard controls with code for WASD.
This reuses the original counters for forward and sideways velocity.+
Double the speed if shift is held down.

W (keycode 0x11)
A (keycode 0x1e)
S (keycode 0x1f)
D (keycode 0x20)
LShift (keycode 0x2a)

[pseudo]
cmp using_alien_abductor, 0
jne skip
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
skip:


[generic]
cmp byte ptr [ds:0x3e949], 0
jne skip
mov dword ptr [ds:0x316b5],1

up:
xor eax,eax
test byte ptr [ds:0x461af+0x11],3
jz down
sub eax,0x4000

down:
test byte ptr [ds:0x461af+0x1f],3
jz leftyrighty
add eax,0x4000

leftyrighty:
test byte ptr [ds:0x461af+0x2a],3
jz apply_fwd
shl eax,1
apply_fwd:
mov dword ptr [ds:0x31445],eax

left:
xor eax,eax
test byte ptr [ds:0x461af+0x1e],3
jz right
sub eax,0xc000

right:
test byte ptr [ds:0x461af+0x20],3
jz fin
add eax,0xc000

fin:
test byte ptr [ds:0x461af+0x2a],3
jz apply_strafe
shl eax,1
apply_strafe:
mov dword ptr [ds:0x31441],eax

and byte ptr [ds:0x461af+0x11],1
and byte ptr [ds:0x461af+0x1f],1
and byte ptr [ds:0x461af+0x1e],1
and byte ptr [ds:0x461af+0x20],1
and byte ptr [ds:0x461af+0x2a],1
skip:
"""

WASD_MOD = b"\x80\x3D\x49\xE9\x03\x00\x00\x0F\x85\x89\x00\x00\x00\xC7\x05\xB5\x16\x03\x00\x01\x00\x00\x00\x31\xC0\xF6\x05\xC0\x61\x04\x00\x03\x74\x05\x2D\x00\x40\x00\x00\xF6\x05\xCE\x61\x04\x00\x03\x74\x05\x05\x00\x40\x00\x00\xF6\x05\xD9\x61\x04\x00\x03\x74\x02\xD1\xE0\xA3\x45\x14\x03\x00\x31\xC0\xF6\x05\xCD\x61\x04\x00\x03\x74\x05\x2D\x00\xC0\x00\x00\xF6\x05\xCF\x61\x04\x00\x03\x74\x05\x05\x00\xC0\x00\x00\xF6\x05\xD9\x61\x04\x00\x03\x74\x02\xD1\xE0\xA3\x41\x14\x03\x00\x80\x25\xC0\x61\x04\x00\x01\x80\x25\xCE\x61\x04\x00\x01\x80\x25\xCD\x61\x04\x00\x01\x80\x25\xCF\x61\x04\x00\x01\x80\x25\xD9\x61\x04\x00\x01"
WASD_OFFSET = 0x5ae36
WASD_REJOIN = 0x5afb8

# calculate relative jump to next bit of code
WASD_MOD += b"\xE9" + utils.to_int32_le(WASD_REJOIN - (WASD_OFFSET + len(WASD_MOD)) - 5)
WASD_MOD_END = len(WASD_MOD) + WASD_OFFSET
# fill gap with nops
WASD_MOD += b"\x90" * (WASD_REJOIN - WASD_MOD_END)

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
DT_OFFSET = 0x59b10

"""
The game normally maps "run" to the R key, but we're using it now, so nop out that code.
"""

RKEY_MOD = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
RKEY_OFFSET = 0x5b0cb


"""
The original control scheme has LCtrl/LAlt to drop eye level, LShift to raise eye level, and 
E to restore to normal eye level. Let's simplify this to crouching while holding C, or reach up on tippytoes while holding R, else restore
to normal eye level.

C (keycode 0x2e)
R (keycode 0x13)

[pseudo]
cmp using_alien_abductor, 0
je start
ret
start:
push ecx
push edx
mov ecx,movement_eye_level_min
add ecx,movement_eye_level_restore

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
mov eax,movement_eye_level
sub eax,ecx
cdq
xor eax, edx
sub eax, edx
cmp eax,movement_eye_level_incr
jle skip

; if eye level > neutral, incr is negative, else positive
mov eax,movement_eye_level_incr
cmp ecx,movement_eye_level
jg adjust
neg eax

; eye level += incr
adjust:
add movement_eye_level,eax
jmp fin

skip:
mov movement_eye_level,ecx

fin:
and keyboard_state[0x2e],1
and keyboard_state[0x13],1
pop edx
pop ecx
ret



[generic]
cmp byte ptr [ds:0x3e949], 0
je start
ret
start:
push ecx
push edx
mov ecx,dword ptr [ds:0x316e1]
add ecx,dword ptr [ds:0x317d0]

test byte ptr [ds:0x461af+0x2e],3
jnz crouch
test byte ptr [ds:0x461af+0x13],3
jz restore 

tippytoes:
mov eax,dword ptr [ds:0x316BD]
add dword ptr [ds:0x317cc],eax
mov eax,dword ptr [ds:0x317cc]
cmp eax,dword ptr [ds:0x316dd]
jle fin
mov eax, dword ptr [ds:0x316dd]
mov dword ptr [ds:0x317cc],eax
jmp fin


crouch:
mov eax,dword ptr [ds:0x316BD]
sub dword ptr [ds:0x317cc],eax
mov eax,dword ptr [ds:0x317cc]
cmp eax,dword ptr [ds:0x316e1]
jge fin
mov eax, dword ptr [ds:0x316e1]
mov dword ptr [ds:0x317cc],eax
jmp fin

restore:
mov eax,dword ptr [ds:0x317cc]
sub eax,ecx
cdq
xor eax, edx
sub eax, edx 
cmp eax,dword ptr [ds:0x316BD]
jle skip

mov eax,dword ptr [ds:0x316BD]
cmp ecx,dword ptr [ds:0x317cc]
jg adjust
neg eax

adjust:
add dword ptr [ds:0x317cc],eax
jmp fin

skip:
mov dword ptr [ds:0x317cc],ecx

fin:
and byte ptr [ds:0x461af+0x2e],1
and byte ptr [ds:0x461af+0x13],1
pop edx
pop ecx
ret


"""

CROUCH_MOD = b"\x80\x3D\x49\xE9\x03\x00\x00\x74\x01\xC3\x51\x52\x8B\x0D\xE1\x16\x03\x00\x03\x0D\xD0\x17\x03\x00\xF6\x05\xDD\x61\x04\x00\x03\x75\x2D\xF6\x05\xC2\x61\x04\x00\x03\x74\x48\xA1\xBD\x16\x03\x00\x01\x05\xCC\x17\x03\x00\xA1\xCC\x17\x03\x00\x3B\x05\xDD\x16\x03\x00\x7E\x63\xA1\xDD\x16\x03\x00\xA3\xCC\x17\x03\x00\xEB\x57\xA1\xBD\x16\x03\x00\x29\x05\xCC\x17\x03\x00\xA1\xCC\x17\x03\x00\x3B\x05\xE1\x16\x03\x00\x7D\x3F\xA1\xE1\x16\x03\x00\xA3\xCC\x17\x03\x00\xEB\x33\xA1\xCC\x17\x03\x00\x29\xC8\x52\x99\x31\xD0\x29\xD0\x5A\x3B\x05\xBD\x16\x03\x00\x7E\x17\xA1\xBD\x16\x03\x00\x3B\x0D\xCC\x17\x03\x00\x7F\x02\xF7\xD8\x01\x05\xCC\x17\x03\x00\xEB\x06\x89\x0D\xCC\x17\x03\x00\x80\x25\xDD\x61\x04\x00\x01\x80\x25\xC2\x61\x04\x00\x01\x5A\x59\xC3"
CROUCH_OFFSET = 0x5ab48

"""
A new feature in Pandora Directive is the Alien Abductor remote control vehicle. 
You won't be surprised to learn that this is basically the same engine as the walking,
only you click on a d-pad instead of adjusting speed with the mouse.

The original code tries to be clever and smoothly ramp the velocity up and down, however
this acceleration is coupled to framerate instead of timer ticks, and runs much too fast 
on modern hardware.

The original code is sprawling and repeats itself a lot, so it's easier to just write a new one.

[pseudo]
cmp fake_key_input, 0x2a
jne hoverdown
mov eax, movement_eye_level
add eax, 0x400
cmp eax, movement_eye_level_max
jl hoverup_write
mov eax, movement_eye_level_max
hoverup_write:
mov movement_eye_level, eax

hoverdown:
cmp fake_key_input, 0x38
jne dpad
mov eax, movement_eye_level
sub eax, 0x400
cmp eax, movement_eye_level_min
jg hoverdown_write
mov eax, movement_eye_level_min
hoverdown_write:
mov movement_eye_level, eax

dpad:
mov al, abductor_state
cmp al, 2
je move

mov movement_rot_veloc_world, 0
mov movement_fwd_veloc_world, 0
jmp fin

move:
test abductor_dpad, 0xc
jz updown
turn:
mov eax, 0x400000
test abductor_dpad, 0x8
jnz leftright_speed
neg eax
leftright_speed:
test keyboard_state[0x2a],3
jz leftright_apply
shl eax,1
leftright_apply:
mov movement_rot_veloc_world, eax 

updown:
test abductor_dpad, 0x3
jz fin
mov eax, 0x1800
test abductor_dpad, 0x2
jnz updown_speed
neg eax
updown_speed:
test keyboard_state[0x2a],3
jz updown_apply
shl eax,1
updown_apply:
mov movement_fwd_veloc_world, eax

fin:
mov mouse_unbounded_x_mod, 0
mov mouse_unbounded_y_mod, 0
and byte ptr keyboard_state[0x2a],1
ret



[generic]
cmp byte ptr [ds:0x3e914], 0x2a
jne hoverdown
mov eax, dword ptr [ds:0x317cc]
add eax, 0x400
cmp eax, dword ptr [ds:0x316dd]
jl hoverup_write
mov eax, dword ptr [ds:0x316dd]
hoverup_write:
mov dword ptr [ds:0x317cc], eax

hoverdown:
cmp  byte ptr [ds:0x3e914], 0x38
jne dpad
mov eax, dword ptr [ds:0x317cc]
sub eax, 0x400
cmp eax, dword ptr [ds:0x316e1]
jg hoverdown_write
mov eax, dword ptr [ds:0x316e1]
hoverdown_write:
mov dword ptr [ds:0x317cc], eax


dpad:
mov al, byte ptr [ds:0x3e945]
cmp al, 2
je move

mov dword ptr [ds:0x31441], 0
mov dword ptr [ds:0x31445], 0
jmp fin

move:
test byte ptr [ds:0x3e946], 0xc
jz updown
turn:
mov eax, 0x400000
test byte ptr [ds:0x3e946], 0x8
jnz leftright_speed
neg eax
leftright_speed:
test byte ptr [ds:0x461af+0x2a],3
jz leftright_apply
shl eax,1
leftright_apply:
mov dword ptr [ds:0x31441], eax 

updown:
test byte ptr [ds:0x3e946], 0x3
jz fin
mov eax, 0x1800
test byte ptr [ds:0x3e946], 0x2
jnz updown_speed
neg eax
updown_speed:
test byte ptr [ds:0x461af+0x2a],3
jz updown_apply
shl eax,1
updown_apply:
mov dword ptr [ds:0x31445], eax

fin:
mov word ptr [ds:0x2018a], 0
mov word ptr [ds:0x2018c], 0
and byte ptr [ds:0x461af+0x2a],1
ret

"""

ABDUCTOR_MOD = b"\x80\x3D\x14\xE9\x03\x00\x2A\x75\x1C\xA1\xCC\x17\x03\x00\x05\x00\x04\x00\x00\x3B\x05\xDD\x16\x03\x00\x7C\x05\xA1\xDD\x16\x03\x00\xA3\xCC\x17\x03\x00\x80\x3D\x14\xE9\x03\x00\x38\x75\x1C\xA1\xCC\x17\x03\x00\x2D\x00\x04\x00\x00\x3B\x05\xE1\x16\x03\x00\x7F\x05\xA1\xE1\x16\x03\x00\xA3\xCC\x17\x03\x00\xA0\x45\xE9\x03\x00\x3C\x02\x74\x16\xC7\x05\x41\x14\x03\x00\x00\x00\x00\x00\xC7\x05\x45\x14\x03\x00\x00\x00\x00\x00\xEB\x52\xF6\x05\x46\xE9\x03\x00\x0C\x74\x20\xB8\x00\x00\x40\x00\xF6\x05\x46\xE9\x03\x00\x08\x75\x02\xF7\xD8\xF6\x05\xD9\x61\x04\x00\x03\x74\x02\xD1\xE0\xA3\x41\x14\x03\x00\xF6\x05\x46\xE9\x03\x00\x03\x74\x20\xB8\x00\x18\x00\x00\xF6\x05\x46\xE9\x03\x00\x02\x75\x02\xF7\xD8\xF6\x05\xD9\x61\x04\x00\x03\x74\x02\xD1\xE0\xA3\x45\x14\x03\x00\x66\xC7\x05\x8A\x01\x02\x00\x00\x00\x66\xC7\x05\x8C\x01\x02\x00\x00\x00\x80\x25\xD9\x61\x04\x00\x01\xC3"
ABDUCTOR_OFFSET = 0x80

"""
Another bit of the alien abductor code injects keyboard presses for the hover up/hover down buttons.
This is bad news, as it relies on the original eye level code that we threw out.
So here we nop out the injection part.
"""

ABDUCTOR_HOVERUP_MOD = b"\x90\x90\x90\x90\x90\x90\x90"
ABDUCTOR_HOVERUP_OFFSET = 0x2a57

ABDUCTOR_HOVERDOWN_MOD = b"\x90\x90\x90\x90\x90\x90\x90"
ABDUCTOR_HOVERDOWN_OFFSET = 0x2902

"""
Tex Murphy does not have any code in the 3D engine to wait for vsync.
This isn't an issue on a 486 running at <5fps, but on DOSBox you get a nice
distracting screen flicker in interactive mode from all of the screen tearing.

To solve this, we shim the start of the function that draws frames in interactive
mode, and have it jump to some new code which calls the VBE 2.0 Set Display Start
method to wait for the vertical retrace to happen.
This won't remove flicker entirely, as the engine is not double-buffered, but it's
a big improvement over doing nothing.

We have a bunch of space left over from WASD_MOD, so shove it in there.
"""
VSYNC_JMP_OFFSET = 0x5a314 # interactive_draw_frame
VSYNC_JMP_MOD = b"\xe9" + utils.to_int32_le(WASD_MOD_END - VSYNC_JMP_OFFSET - 5)

VSYNC_RETURN_OFFSET = 0x5a31f

"""
Vsync shim.

[generic]
push eax
push ebx
push ecx
push edx
mov ax, 0x4f07
mov bx, 0x0080
mov cx, 0x0000
mov dx, 0x0000
int 0x10
pop edx
pop ecx
pop ebx
pop eax

push es
pusha
mov word ptr [ds:0x31538], 0

"""
VSYNC_OFFSET = WASD_MOD_END
VSYNC_MOD = b"\x50\x53\x51\x52\x66\xB8\x07\x4F\x66\xBB\x80\x00\x66\xB9\x00\x00\x66\xBA\x00\x00\xCD\x10\x5A\x59\x5B\x58\x06\x60\x66\xC7\x05\x38\x15\x03\x00\x00\x00"
VSYNC_MOD += b"\xe9" + utils.to_int32_le(VSYNC_RETURN_OFFSET - len(VSYNC_MOD) - WASD_MOD_END - 5)


CODE_PATCHES = [
    (MOUSELOOK_CODE, MOUSELOOK_OFFSET),
    (WASD_MOD, WASD_OFFSET),
    (DT_MOD, DT_OFFSET),
    (RKEY_MOD, RKEY_OFFSET),
    (CROUCH_MOD, CROUCH_OFFSET),
    (ABDUCTOR_MOD, ABDUCTOR_OFFSET),
    (ABDUCTOR_HOVERUP_MOD, ABDUCTOR_HOVERUP_OFFSET),
    (ABDUCTOR_HOVERDOWN_MOD, ABDUCTOR_HOVERDOWN_OFFSET),
    (VSYNC_JMP_MOD, VSYNC_JMP_OFFSET),
    (VSYNC_MOD, VSYNC_OFFSET),
]

DATA_PATCHES = [
]


f = open('TEX4.EXE', 'rb').read()
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
                  iced_x86.Code.CMP_RM8_IMM8 |
                  iced_x86.Code.MOV_R8_RM8 |
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
            case (iced_x86.Code.MOV_RM16_IMM16):
                fixup = FixupTuple("fix_32off_32", 0x7, 0x10, DATA_OBJ, srcoff+3, utils.from_uint32_le(mod_code[instr.ip+3:instr.ip+7]))
                print((page, None, hex(offset), fixup))
                fixup_records[page].append(fixup)
            case (iced_x86.Code.JMP_RM32):
                fixup = FixupTuple("fix_32off_32", 0x7, 0x10, CODE_OBJ, srcoff+3, utils.from_uint32_le(mod_code[instr.ip+3:instr.ip+7]))
                print((page, None, hex(offset), fixup))
                fixup_records[page].append(fixup)

    page_data[mod_offset:mod_offset+len(mod_code)] = mod_code

for mod_data, mod_offset in DATA_PATCHES:
    page_data[mod_offset:mod_offset+len(mod_data)] = mod_data

with open("TEX4MOD.EXE", "wb") as out:
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

# IDA hates the original two-stage DOS4GW embedding
with open("TEX4MODRAW.EXE", "wb") as g:
    f = open("TEX4MOD.EXE", "rb").read()
    g.write(f[0x000352a4:])
