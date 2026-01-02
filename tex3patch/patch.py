#!/usr/bin/env python3

import pathlib

from iced_x86 import (
    BlockEncoder,
    Code,
    Decoder,
    Instruction,
    InstructionInfoFactory,
    MemoryOperand,
    Register,
)
from mrcrowbar import utils

from .le import (
    FixupPageTable,
    FixupTuple,
    LEHeader,
    ObjectPageTable,
    ObjectTable,
    fixups_decode,
    fixups_encode,
    search_for_le,
)

label_id: int = 1


def create_label() -> int:
    global label_id
    idd = label_id
    label_id += 1
    return idd


def add_label(id: int, instruction: Instruction) -> Instruction:
    instruction.ip = id
    return instruction


def memory(offset: int) -> MemoryOperand:
    return MemoryOperand(Register.NONE, displ=offset, displ_size=4)


def assemble_x86(data: list[Instruction]) -> bytes:
    # print(data)
    enc = BlockEncoder(32)
    enc.add_many(data)
    result = enc.encode(0)
    # print(result.hex())
    return result


class DataNotFound(Exception):
    pass


def detect_version(page_data: bytearray) -> tuple[str, str, str]:
    # Scrape title + version number from the command line version screen
    VERSION_PATTERN = "\\xda\\xc4+\\xbf(?:\\x0a\\x0d|\\x0d\\x0a)\\xb3\\x20+([A-Za-z ]+)\\x20+\\xb3(?:\\x0a\\x0d|\\x0d\\x0a)\\xb3\\x20+Version ([0-9\\.]+)\\x20+\\xb3"
    result = utils.grep(VERSION_PATTERN, page_data)
    if not result:
        raise DataNotFound(
            "Failed to detect Under a Killing Moon or The Pandora Directive! Please create an issue on https://github.com/moralrecordings/tex3-mouselook"
        )
    game, version = result[0].group(1).decode("ascii"), result[0].group(2).decode(
        "ascii"
    )

    # Apparently there's one debug message which has the language in it
    LANGUAGE_PATTERN = "\\x00([A-Za-z]+)\\x00Retrieving DIGI settings"
    result = utils.grep(LANGUAGE_PATTERN, page_data)
    language = "UNKNOWN"
    if result:
        language = result[0].group(1).decode("ascii")

    if game not in ("Under a Killing Moon", "The Pandora Directive"):
        raise DataNotFound(
            f'Unknown game {game}, must be one of "Under a Killing Moon" or "The Pandora Directive"'
        )

    print(f"Found {game} v{version}, {language.title()} language")
    return game, version, language


def find_offset(
    page_data: bytearray, pattern: str, offset: int, description: str
) -> int:
    if not pattern:
        raise DataNotFound(f"No pattern for {description}, aborting")
    matches = utils.grep(pattern, page_data)
    if not matches:
        raise DataNotFound(f"Could not find offset for {description}, aborting")
    if len(matches) > 1:
        raise DataNotFound(
            f"Multiple offset matches found for {description} ({matches}), aborting"
        )
    result = matches[0].start() + offset
    print(f"Offset for {description} found at 0x{result:08x}")
    return result


def find_variable(page_data: bytearray, pattern: str, description: str) -> int:
    if not pattern:
        raise DataNotFound(f"No pattern for {description}, aborting")
    matches = utils.grep(pattern, page_data)
    if not matches:
        raise DataNotFound(f"Could not find variable for {description}, aborting")
    if len(matches) > 1:
        raise DataNotFound(
            f"Multiple variable matches found for {description} ({matches}), aborting"
        )
    result = utils.from_uint32_le(matches[0].group(1))
    print(f"Variable for {description} found at 0x{result:08x}")
    return result


def patch(
    input: pathlib.Path,
    output: pathlib.Path,
    fix_speed: bool,
    mouselook: bool,
    invert_y: bool,
) -> None:
    f = open(input, "rb").read()
    # read the LE header from the executable
    mz_off, le_off = search_for_le(f)
    le_header = LEHeader(f[le_off:])

    # loader_section, fixup_section, data_section, debug_section

    # extract the various fixup tables used to hotpatch addresses.
    # for any areas of code we patch, we will have to remove the old fixups and sub in new ones.
    fixup_page_table = FixupPageTable(
        f[le_off + le_header.fixup_page_table_offset :][
            : 4 * (le_header.module_num_pages + 1)
        ]
    )
    fixup_record_table = []
    for i in range(le_header.module_num_pages):
        fixup_record_table.append(
            f[le_off + le_header.fixup_record_table_offset :][
                fixup_page_table.offsets[i] : fixup_page_table.offsets[i + 1]
            ]
        )

    fixup_records = [fixups_decode(x) for x in fixup_record_table]
    object_table = ObjectTable(
        f[le_off + le_header.obj_table_offset :][: le_header.obj_count * 0x18]
    )
    object_page_table = ObjectPageTable(
        f[le_off + le_header.obj_page_table_offset :][
            : le_header.module_num_pages * 0x4
        ]
    )

    # extract the code and data segments
    page_data_orig = f[mz_off + le_header.data_pages_offset :]
    page_data = bytearray(page_data_orig)

    iff = InstructionInfoFactory()

    # scrape version information
    name, version, language = detect_version(page_data)

    CODE_PATCHES: list[tuple[bytes, int]] = []
    DATA_PATCHES: list[tuple[bytes, int]] = []

    if fix_speed:
        """
        The game engine measures the number of ticks between redraws, and multiplies this delta time value
        by the movement velocity to get the displacement.

        For reasons that are unclear, if 0 ticks have elapsed, the engine rounds this up to 4.
        Which means e.g. in areas of low geometry, Tex will start rocketing around far too quickly.
        This happens in the original movement code as well, adding to the difficulty of the controls.
        Fix this by nopping out that section of code.

        """
        fix_speed_offset = find_offset(
            page_data,
            "\\xf7\\xd8\\x83\\xc0\\x64\\x75\\x05\\xb8\\x04\\x00\\x00\\x00",
            5,
            "speed bug code",
        )
        fix_speed_code = assemble_x86([Instruction.create(Code.NOPD)] * 7)
        CODE_PATCHES.append((fix_speed_code, fix_speed_offset))

    if mouselook:

        # Find data segment locations of stuff we need to wire up to.
        # These shuffle around a lot, but the code for accessing them is basically
        # the same across versions; use that as a basis.
        var_movement_rot_angle = find_variable(
            page_data,
            "\\xa3(.{4})\\xc1\\xf8\\x10\\xe8.{4}\\xa1.{4}",
            "head rotation angle",
        )
        var_movement_tilt_angle = find_variable(
            page_data, "\\xc7\\x05(.{4})\\x2c\\x01\\x00\\x00", "head tilt angle"
        )
        var_movement_tilt_angle_last = find_variable(
            page_data,
            "\\xa3(.{4})\\xa1.{4}\\x0b\\xc0\\x74\\x2c",
            "last head tilt angle",
        )
        var_movement_tilt_angle_bottom = find_variable(
            page_data,
            "\\xa1(.{4})\\xa3.{4}\\xa3.{4}\\x0f\\xb6\\x1d.{4}",
            "min head tilt angle",
        )
        var_movement_tilt_angle_top = find_variable(
            page_data,
            "\\xa1(.{4})\\xa3.{4}\\xa3.{4}\\xa1.{4}\\x0b\\xc0",
            "max head tilt angle",
        )
        var_movement_strafe = find_variable(
            page_data, "\\x83\\x25(.{4})\\xfc\\x66\\x0f.{4}", "strafe flag"
        )
        var_keyboard_state = find_variable(
            page_data, "\\xb9\\x2c\\x00\\x00\\x00\\xbf(.{4})", "keyboard state array"
        )
        var_movement_fwd_veloc_world = find_variable(
            page_data,
            "\\xf7\\x2d.{4}\\x0f\\xac\\xd0\\x10\\xa3(.{4})\\x8b\\xc1",
            "forward velocity",
        )
        var_movement_strafe_veloc_world = find_variable(
            page_data,
            "\\x0b\\xed\\x79\\x02\\xf7\\xd8\\xa3(.{4})\\xc3",
            "strafe velocity",
        )
        var_movement_eye_level_incr = find_variable(
            page_data,
            "\\x80\\xa0.{4}\\x01\\x80\\xa3.{4}\\x01\\xa1(.{4})",
            "eye level increment",
        )
        var_movement_eye_level = find_variable(
            page_data,
            "\\x80\\xa0.{4}\\x01\\x80\\xa3.{4}\\x01\\xa1.{4}\\x29\\x05(.{4})",
            "eye level",
        )
        var_movement_eye_level_max = find_variable(
            page_data, "\\xc1\\xe1\\x0c\\x03\\xc1\\xa3(.{4})", "max eye level"
        )
        var_movement_eye_level_min = find_variable(
            page_data,
            "\\x83\\xf8\\x00\\x74\\x1f\\xe8.{4}\\x2b\\x05(.{4})",
            "min eye level",
        )
        var_movement_eye_level_restore = find_variable(
            page_data, "\\x2b\\xd0\\x89\\x15(.{4})", "default eye level"
        )

        var_using_alien_abductor = None
        var_abductor_state = None
        var_abductor_dpad = None
        var_fake_key_input = None
        var_mouse_unbounded_x_mod = None
        var_mouse_unbounded_y_mod = None
        if name == "The Pandora Directive":
            var_using_alien_abductor = find_variable(
                page_data,
                "\\x88\\x45\\xfc\\xf6\\x45\\xfc\\x02\\x75\\x05\\xe8.{4}\\xe8.{4}\\xc6\\x05(.{4})\\x01",
                "Alien Abductor flag",
            )
            var_abductor_state = find_variable(
                page_data,
                "\\x8b\\x45\\xf0\\x80\\x88.{4}\\x02\\x80\\x3d(.{4})\\x02",
                "Alien Abductor state",
            )
            var_abductor_dpad = find_variable(
                page_data,
                "\\xf7\\xd8\\x89\\x45\\xf8\\xf6\\x05(.{4})\\x04",
                "Alien Abductor directional pad state",
            )
            var_fake_key_input = find_variable(
                page_data,
                "\\xc7\\x45\\xf4\\x00\\x00\\x00\\x00\\xc7\\x45\\xfc(.{4})\\x8b\\x45\\xfc",
                "Alien Abductor key input buffer",
            )
            var_mouse_unbounded_x_mod = find_variable(
                page_data,
                "\\xe9\\x1f\\x02\\x00\\x00\\xc7\\x45\\xfc\\x0c\\x00\\x00\\x00\\x66\\xc7\\x05(.{4})\\x00\\x00\\x66\\xc7\\x05.{4}\\x00\\x00",
                "Alien Abductor mouse X buffer",
            )
            var_mouse_unbounded_y_mod = find_variable(
                page_data,
                "\\xe9\\x1f\\x02\\x00\\x00\\xc7\\x45\\xfc\\x0c\\x00\\x00\\x00\\x66\\xc7\\x05.{4}\\x00\\x00\\x66\\xc7\\x05(.{4})\\x00\\x00",
                "Alien Abductor mouse Y buffer",
            )

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
"""
        mouselook_offset = find_offset(
            page_data,
            "\\x8b\\xc2\\x33\\xed\\x03\\x05.{4}\\x8b\\xd8",
            0,
            "mouselook mod point",
        )
        label_check2 = create_label()
        label_after = create_label()
        invert_code = (
            []
            if not invert_y
            else [Instruction.create_reg(Code.NEG_RM32, Register.EAX)]
        )
        mouselook_instrs = assemble_x86(
            [
                Instruction.create_reg_reg(
                    Code.MOV_RM32_R32, Register.EAX, Register.ECX
                ),
                Instruction.create_reg_u32(Code.SHL_RM32_IMM8, Register.EAX, 17),
                Instruction.create_mem_reg(
                    Code.ADD_RM32_R32, memory(var_movement_rot_angle), Register.EAX
                ),
                Instruction.create_reg_reg(
                    Code.MOV_RM32_R32, Register.EAX, Register.EDX
                ),
                *invert_code,
                Instruction.create_reg_u32(Code.SHL_RM32_1, Register.EAX, 1),
                Instruction.create_reg_mem(
                    Code.ADD_R32_RM32,
                    Register.EAX,
                    memory(var_movement_tilt_angle_last),
                ),
                Instruction.create_reg_mem(
                    Code.CMP_R32_RM32, Register.EAX, memory(var_movement_tilt_angle_top)
                ),
                Instruction.create_branch(Code.JGE_REL8_32, label_check2),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32,
                    Register.EAX,
                    memory(var_movement_tilt_angle_top),
                ),
                add_label(
                    label_check2,
                    Instruction.create_reg_mem(
                        Code.CMP_R32_RM32,
                        Register.EAX,
                        memory(var_movement_tilt_angle_bottom),
                    ),
                ),
                Instruction.create_branch(Code.JLE_REL8_32, label_after),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32,
                    Register.EAX,
                    memory(var_movement_tilt_angle_bottom),
                ),
                add_label(
                    label_after,
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS32_EAX,
                        memory(var_movement_tilt_angle),
                        Register.EAX,
                    ),
                ),
                Instruction.create_mem_reg(
                    Code.MOV_MOFFS32_EAX,
                    memory(var_movement_tilt_angle_last),
                    Register.EAX,
                ),
                Instruction.create(Code.RETND),
            ]
        )
        CODE_PATCHES.append((mouselook_instrs, mouselook_offset))

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
nop
jmp wasd_rejoin
"""
        wasd_offset = find_offset(
            page_data,
            "\\x80\\x3d.{4}\\x00\\x0f\\x84\\x93\\x00\\x00\\x00\\x33\\xc0",
            0,
            "WASD mod point",
        )
        wasd_rejoin = find_offset(
            page_data,
            "\\x0f\\xb6\\x1d.{4}\\x80\\xa3.{4}\\x01" * 7,
            0,
            "WASD rejoin mod point",
        )
        label_up = create_label()
        label_down = create_label()
        label_leftyrighty = create_label()
        label_apply_fwd = create_label()
        label_left = create_label()
        label_right = create_label()
        label_fin = create_label()
        label_apply_strafe = create_label()
        label_skip = create_label()

        abductor_prefix = (
            []
            if not var_using_alien_abductor
            else [
                Instruction.create_mem_i32(
                    Code.CMP_RM8_IMM8, memory(var_using_alien_abductor), 0
                ),
                Instruction.create_branch(Code.JNE_REL8_32, label_skip),
            ]
        )

        wasd_instrs = assemble_x86(
            [
                *abductor_prefix,
                Instruction.create_mem_u32(
                    Code.MOV_RM32_IMM32, memory(var_movement_strafe), 1
                ),
                add_label(
                    label_up,
                    Instruction.create_reg_reg(
                        Code.XOR_RM32_R32, Register.EAX, Register.EAX
                    ),
                ),
                Instruction.create_mem_u32(
                    Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x11), 3
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_down),
                Instruction.create_reg_i32(Code.SUB_EAX_IMM32, Register.EAX, 0x4000),
                add_label(
                    label_down,
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x1F), 3
                    ),
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_leftyrighty),
                Instruction.create_reg_i32(Code.ADD_EAX_IMM32, Register.EAX, 0x4000),
                add_label(
                    label_leftyrighty,
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x2A), 3
                    ),
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_apply_fwd),
                Instruction.create_reg_u32(Code.SHL_RM32_1, Register.EAX, 1),
                add_label(
                    label_apply_fwd,
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS32_EAX,
                        memory(var_movement_fwd_veloc_world),
                        Register.EAX,
                    ),
                ),
                add_label(
                    label_left,
                    Instruction.create_reg_reg(
                        Code.XOR_RM32_R32, Register.EAX, Register.EAX
                    ),
                ),
                Instruction.create_mem_i32(
                    Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x1E), 3
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_right),
                Instruction.create_reg_i32(Code.SUB_EAX_IMM32, Register.EAX, 0xC000),
                add_label(
                    label_right,
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x20), 3
                    ),
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_fin),
                Instruction.create_reg_i32(Code.ADD_EAX_IMM32, Register.EAX, 0xC000),
                add_label(
                    label_fin,
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x2A), 3
                    ),
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_apply_strafe),
                Instruction.create_reg_i32(Code.SHL_RM32_1, Register.EAX, 1),
                add_label(
                    label_apply_strafe,
                    Instruction.create_mem_reg(
                        Code.MOV_MOFFS32_EAX,
                        memory(var_movement_strafe_veloc_world),
                        Register.EAX,
                    ),
                ),
                Instruction.create_mem_u32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x11), 1
                ),
                Instruction.create_mem_u32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x1F), 1
                ),
                Instruction.create_mem_u32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x1E), 1
                ),
                Instruction.create_mem_u32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x20), 1
                ),
                Instruction.create_mem_u32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x2A), 1
                ),
                add_label(label_skip, Instruction.create(Code.NOPD)),
            ]
        )

        # calculate relative jump to next bit of code
        wasd_instrs += assemble_x86(
            [
                Instruction.create_branch(
                    Code.JMP_REL32_32,
                    wasd_rejoin - (wasd_offset + len(wasd_instrs)) - 5,
                ),
            ]
        )
        wasd_mod_end = len(wasd_instrs) + wasd_offset
        # fill gap with nops
        wasd_instrs += assemble_x86(
            [Instruction.create(Code.NOPD)] * (wasd_rejoin - wasd_mod_end)
        )
        CODE_PATCHES.append((wasd_instrs, wasd_offset))

        """
The game normally maps "run" to the R key, but we're using it now, so nop out that code.
"""
        rkey_mod_offset = find_offset(
            page_data,
            "\\x0f\\xb6\\x1d.{4}\\xf6\\x83.{4}\\x01\\x75\\x0c\\x66\\xb9\\x02\\x00\\x2a\\x0d.{4}\\xd3\\xf8",
            0,
            "R key mod point",
        )
        rkey_mod_code = assemble_x86([Instruction.create(Code.NOPD)] * 28)
        CODE_PATCHES.append((rkey_mod_code, rkey_mod_offset))

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

"""
        crouch_mod_offset = find_offset(
            page_data,
            "\\x0f\\xb6\\x05.{4}\\x0f\\xb6\\x1d.{4}\\xf6\\x80.{4}\\x03",
            0,
            "crouch mod point",
        )

        label_start = create_label()
        label_tippytoes = create_label()
        label_crouch = create_label()
        label_restore = create_label()
        label_adjust = create_label()
        label_skip = create_label()
        label_fin = create_label()
        abductor_prefix = (
            []
            if not var_using_alien_abductor
            else [
                Instruction.create_mem_i32(
                    Code.CMP_RM8_IMM8, memory(var_using_alien_abductor), 0
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_start),
                Instruction.create(Code.RETND),
            ]
        )
        crouch_instrs = assemble_x86(
            [
                *abductor_prefix,
                add_label(
                    label_start, Instruction.create_reg(Code.PUSH_R32, Register.ECX)
                ),
                Instruction.create_reg(Code.PUSH_R32, Register.EDX),
                Instruction.create_reg_mem(
                    Code.MOV_R32_RM32, Register.ECX, memory(var_movement_eye_level_min)
                ),
                Instruction.create_reg_mem(
                    Code.ADD_R32_RM32,
                    Register.ECX,
                    memory(var_movement_eye_level_restore),
                ),
                Instruction.create_mem_i32(
                    Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x2E), 3
                ),
                Instruction.create_branch(Code.JNE_REL8_32, label_crouch),
                Instruction.create_mem_i32(
                    Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x13), 3
                ),
                Instruction.create_branch(Code.JE_REL8_32, label_restore),
                add_label(
                    label_tippytoes,
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level_incr),
                    ),
                ),
                Instruction.create_mem_reg(
                    Code.ADD_RM32_R32, memory(var_movement_eye_level), Register.EAX
                ),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32, Register.EAX, memory(var_movement_eye_level)
                ),
                Instruction.create_reg_mem(
                    Code.CMP_R32_RM32, Register.EAX, memory(var_movement_eye_level_max)
                ),
                Instruction.create_branch(Code.JLE_REL8_32, label_fin),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32,
                    Register.EAX,
                    memory(var_movement_eye_level_max),
                ),
                Instruction.create_mem_reg(
                    Code.MOV_MOFFS32_EAX, memory(var_movement_eye_level), Register.EAX
                ),
                Instruction.create_branch(Code.JMP_REL8_32, label_fin),
                add_label(
                    label_crouch,
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level_incr),
                    ),
                ),
                Instruction.create_mem_reg(
                    Code.SUB_RM32_R32, memory(var_movement_eye_level), Register.EAX
                ),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32, Register.EAX, memory(var_movement_eye_level)
                ),
                Instruction.create_reg_mem(
                    Code.CMP_R32_RM32, Register.EAX, memory(var_movement_eye_level_min)
                ),
                Instruction.create_branch(Code.JGE_REL8_32, label_fin),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32,
                    Register.EAX,
                    memory(var_movement_eye_level_min),
                ),
                Instruction.create_mem_reg(
                    Code.MOV_MOFFS32_EAX, memory(var_movement_eye_level), Register.EAX
                ),
                Instruction.create_branch(Code.JMP_REL8_32, label_fin),
                add_label(
                    label_restore,
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level),
                    ),
                ),
                Instruction.create_reg_reg(
                    Code.SUB_R32_RM32, Register.EAX, Register.ECX
                ),
                Instruction.create(Code.CDQ),
                Instruction.create_reg_reg(
                    Code.XOR_RM32_R32, Register.EAX, Register.EDX
                ),
                Instruction.create_reg_reg(
                    Code.SUB_R32_RM32, Register.EAX, Register.EDX
                ),
                Instruction.create_reg_mem(
                    Code.CMP_R32_RM32, Register.EAX, memory(var_movement_eye_level_incr)
                ),
                Instruction.create_branch(Code.JLE_REL8_32, label_skip),
                Instruction.create_reg_mem(
                    Code.MOV_EAX_MOFFS32,
                    Register.EAX,
                    memory(var_movement_eye_level_incr),
                ),
                Instruction.create_reg_mem(
                    Code.CMP_R32_RM32, Register.ECX, memory(var_movement_eye_level)
                ),
                Instruction.create_branch(Code.JG_REL8_32, label_adjust),
                Instruction.create_reg(Code.NEG_RM32, Register.EAX),
                add_label(
                    label_adjust,
                    Instruction.create_mem_reg(
                        Code.ADD_RM32_R32, memory(var_movement_eye_level), Register.EAX
                    ),
                ),
                Instruction.create_branch(Code.JMP_REL8_32, label_fin),
                add_label(
                    label_skip,
                    Instruction.create_mem_reg(
                        Code.MOV_RM32_R32, memory(var_movement_eye_level), Register.ECX
                    ),
                ),
                add_label(
                    label_fin,
                    Instruction.create_mem_i32(
                        Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x2E), 1
                    ),
                ),
                Instruction.create_mem_i32(
                    Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x13), 1
                ),
                Instruction.create_reg(Code.POP_R32, Register.EDX),
                Instruction.create_reg(Code.POP_R32, Register.ECX),
                Instruction.create(Code.RETND),
            ]
        )
        CODE_PATCHES.append((crouch_instrs, crouch_mod_offset))

        """
Tex Murphy does not have any code in the 3D engine to wait for vsync.
This isn't an issue on a 486 running at <5fps, but on DOSBox you get a nice
distracting screen flicker in interactive mode from all of the screen tearing.

To improve this, we shim the function that draws frames in interactive mode, 
and have it jump to some new code which calls the VBE 2.0 Set Display Start
method to wait for the vertical retrace to happen.
This won't remove flicker entirely, as the engine is not double-buffered, but it's
a big improvement over doing nothing.

We have a bunch of space left over from WASD_MOD, so shove it in there.

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
"""
        vsync_offset = wasd_mod_end
        # this is a case where PD has a very different function
        # structure compared to UAKM, so we need two detection pathways

        # there's a function that gets called at the start of the
        # "interactive mode" update loop; we need to find it, then
        # overwrite any calls to it to point to our shim.
        interactive_draw_frame_offset = 0
        if name == "Under a Killing Moon":
            interactive_draw_frame_offset = find_offset(
                page_data, "\\x3a\\x05.{4}\\x74\\x22", 0, "interactive frame draw code"
            )
            call1_offset = find_offset(
                page_data, "\\xe8.{4}\\x9c\\x0f\\xb6\\xc0", 0, "frame call 1"
            )
            call1_instrs = b"\xe8" + utils.to_int32_le(
                vsync_offset - (call1_offset + 5)
            )
            CODE_PATCHES.append((call1_instrs, call1_offset))
        elif name == "The Pandora Directive":
            interactive_draw_frame_offset = find_offset(
                page_data,
                "\\x06\\x60\\x66\\xc7\\x05.{4}\\x00\\x00\\xa8\\x01",
                0,
                "interactive frame draw code",
            )
            call1_offset = find_offset(
                page_data, "\\xe8.{4}\\x89\\x45\\xf8\\xb8.{4}", 0, "frame call 1"
            )
            call1_instrs = b"\xe8" + utils.to_int32_le(
                vsync_offset - (call1_offset + 5)
            )
            CODE_PATCHES.append((call1_instrs, call1_offset))
            call2_offset = find_offset(
                page_data, "\\xe8.{4}\\x89\\x45\\xf4\\xb8.{4}", 0, "frame call 2"
            )
            call2_instrs = b"\xe8" + utils.to_int32_le(
                vsync_offset - (call2_offset + 5)
            )
            CODE_PATCHES.append((call2_instrs, call2_offset))
        # shim, which waits for vsync then runs the original function
        vsync_instrs = assemble_x86(
            [
                Instruction.create_reg(Code.PUSH_R32, Register.EAX),
                Instruction.create_reg(Code.PUSH_R32, Register.EBX),
                Instruction.create_reg(Code.PUSH_R32, Register.ECX),
                Instruction.create_reg(Code.PUSH_R32, Register.EDX),
                Instruction.create_reg_u32(Code.MOV_R16_IMM16, Register.AX, 0x4F07),
                Instruction.create_reg_u32(Code.MOV_R16_IMM16, Register.BX, 0x0080),
                Instruction.create_reg_u32(Code.MOV_R16_IMM16, Register.CX, 0x0000),
                Instruction.create_reg_u32(Code.MOV_R16_IMM16, Register.DX, 0x0000),
                Instruction.create_u32(Code.INT_IMM8, 0x10),
                Instruction.create_reg(Code.POP_R32, Register.EDX),
                Instruction.create_reg(Code.POP_R32, Register.ECX),
                Instruction.create_reg(Code.POP_R32, Register.EBX),
                Instruction.create_reg(Code.POP_R32, Register.EAX),
            ]
        )
        # add a JMP_REL32_32
        vsync_instrs += b"\xe9" + utils.to_int32_le(
            interactive_draw_frame_offset - (vsync_offset + len(vsync_instrs) + 5)
        )
        CODE_PATCHES.append((vsync_instrs, vsync_offset))

        if (
            var_using_alien_abductor
            and var_abductor_state
            and var_abductor_dpad
            and var_fake_key_input
            and var_mouse_unbounded_x_mod
            and var_mouse_unbounded_y_mod
        ):
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
            """
            abductor_offset = find_offset(
                page_data,
                "\\x53\\x51\\x52\\x56\\x57\\x55\\x89\\xe5\\x81\\xec\\x0c\\x00\\x00\\x00\\xeb\\x10",
                0,
                "Alien Abductor control buttons",
            )
            label_hoverup_write = create_label()
            label_hoverdown = create_label()
            label_hoverdown_write = create_label()
            label_dpad = create_label()
            label_move = create_label()
            label_turn = create_label()
            label_leftright_speed = create_label()
            label_leftright_apply = create_label()
            label_updown = create_label()
            label_updown_speed = create_label()
            label_updown_apply = create_label()
            label_fin = create_label()

            abductor_instrs = assemble_x86(
                [
                    Instruction.create_mem_i32(
                        Code.CMP_RM8_IMM8, memory(var_fake_key_input), 0x2A
                    ),
                    Instruction.create_branch(Code.JNE_REL8_32, label_hoverdown),
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level),
                    ),
                    Instruction.create_reg_i32(Code.ADD_EAX_IMM32, Register.EAX, 0x400),
                    Instruction.create_reg_mem(
                        Code.CMP_R32_RM32,
                        Register.EAX,
                        memory(var_movement_eye_level_max),
                    ),
                    Instruction.create_branch(Code.JL_REL8_32, label_hoverup_write),
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level_max),
                    ),
                    add_label(
                        label_hoverup_write,
                        Instruction.create_mem_reg(
                            Code.MOV_MOFFS32_EAX,
                            memory(var_movement_eye_level),
                            Register.EAX,
                        ),
                    ),
                    add_label(
                        label_hoverdown,
                        Instruction.create_mem_i32(
                            Code.CMP_RM8_IMM8, memory(var_fake_key_input), 0x38
                        ),
                    ),
                    Instruction.create_branch(Code.JNE_REL8_32, label_dpad),
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level),
                    ),
                    Instruction.create_reg_i32(Code.SUB_EAX_IMM32, Register.EAX, 0x400),
                    Instruction.create_reg_mem(
                        Code.CMP_R32_RM32,
                        Register.EAX,
                        memory(var_movement_eye_level_min),
                    ),
                    Instruction.create_branch(Code.JG_REL8_32, label_hoverdown_write),
                    Instruction.create_reg_mem(
                        Code.MOV_EAX_MOFFS32,
                        Register.EAX,
                        memory(var_movement_eye_level_min),
                    ),
                    add_label(
                        label_hoverdown_write,
                        Instruction.create_mem_reg(
                            Code.MOV_MOFFS32_EAX,
                            memory(var_movement_eye_level),
                            Register.EAX,
                        ),
                    ),
                    add_label(
                        label_dpad,
                        Instruction.create_reg_mem(
                            Code.MOV_AL_MOFFS8, Register.AL, memory(var_abductor_state)
                        ),
                    ),
                    Instruction.create_reg_i32(Code.CMP_AL_IMM8, Register.AL, 2),
                    Instruction.create_branch(Code.JE_REL8_32, label_move),
                    Instruction.create_mem_i32(
                        Code.MOV_RM32_IMM32, memory(var_movement_strafe_veloc_world), 0
                    ),
                    Instruction.create_mem_i32(
                        Code.MOV_RM32_IMM32, memory(var_movement_fwd_veloc_world), 0
                    ),
                    Instruction.create_branch(Code.JMP_REL8_32, label_fin),
                    add_label(
                        label_move,
                        Instruction.create_mem_i32(
                            Code.TEST_RM8_IMM8, memory(var_abductor_dpad), 0xC
                        ),
                    ),
                    Instruction.create_branch(Code.JE_REL8_32, label_updown),
                    add_label(
                        label_turn,
                        Instruction.create_reg_u32(
                            Code.MOV_R32_IMM32, Register.EAX, 0x400000
                        ),
                    ),
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_abductor_dpad), 0x8
                    ),
                    Instruction.create_branch(Code.JNE_REL8_32, label_leftright_speed),
                    Instruction.create_reg(Code.NEG_RM32, Register.EAX),
                    add_label(
                        label_leftright_speed,
                        Instruction.create_mem_i32(
                            Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x2A), 3
                        ),
                    ),
                    Instruction.create_branch(Code.JE_REL8_32, label_leftright_apply),
                    Instruction.create_reg_i32(Code.SHL_RM32_1, Register.EAX, 1),
                    add_label(
                        label_leftright_apply,
                        Instruction.create_mem_reg(
                            Code.MOV_MOFFS32_EAX,
                            memory(var_movement_strafe_veloc_world),
                            Register.EAX,
                        ),
                    ),
                    add_label(
                        label_updown,
                        Instruction.create_mem_i32(
                            Code.TEST_RM8_IMM8, memory(var_abductor_dpad), 3
                        ),
                    ),
                    Instruction.create_branch(Code.JE_REL8_32, label_fin),
                    Instruction.create_reg_u32(
                        Code.MOV_R32_IMM32, Register.EAX, 0x1800
                    ),
                    Instruction.create_mem_i32(
                        Code.TEST_RM8_IMM8, memory(var_abductor_dpad), 2
                    ),
                    Instruction.create_branch(Code.JNE_REL8_32, label_updown_speed),
                    Instruction.create_reg(Code.NEG_RM32, Register.EAX),
                    add_label(
                        label_updown_speed,
                        Instruction.create_mem_i32(
                            Code.TEST_RM8_IMM8, memory(var_keyboard_state + 0x2A), 3
                        ),
                    ),
                    Instruction.create_branch(Code.JE_REL8_32, label_updown_apply),
                    Instruction.create_reg_i32(Code.SHL_RM32_1, Register.EAX, 1),
                    add_label(
                        label_updown_apply,
                        Instruction.create_mem_reg(
                            Code.MOV_MOFFS32_EAX,
                            memory(var_movement_fwd_veloc_world),
                            Register.EAX,
                        ),
                    ),
                    add_label(
                        label_fin,
                        Instruction.create_mem_i32(
                            Code.MOV_RM16_IMM16, memory(var_mouse_unbounded_x_mod), 0
                        ),
                    ),
                    Instruction.create_mem_i32(
                        Code.MOV_RM16_IMM16, memory(var_mouse_unbounded_y_mod), 0
                    ),
                    Instruction.create_mem_i32(
                        Code.AND_RM8_IMM8, memory(var_keyboard_state + 0x2A), 1
                    ),
                    Instruction.create(Code.RETND),
                ]
            )
            CODE_PATCHES.append((abductor_instrs, abductor_offset))

            """
Another bit of the alien abductor code injects keyboard presses for the hover up/hover down buttons.
This is bad news, as it relies on the original eye level code that we threw out.
So here we nop out the injection part.
"""

            abductor_hoverup_offset = find_offset(
                page_data,
                "\\x80\\x88.{4}\\x02\\xc6\\x05.{4}\\x00\\xc6\\x05.{4}\\x00\\x31\\xc0\\xe8.{4}\\x80\\x3d.{4}\\x00\\x74\\x1e\\xe8.{4}\\xba\\x01\\x00\\x00\\x00\\xb8\\x04\\x00\\x00\\x00",
                0,
                "Alien Abductor hover-up button",
            )
            abductor_hoverup_instrs = assemble_x86(
                [
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                ]
            )
            CODE_PATCHES.append((abductor_hoverup_instrs, abductor_hoverup_offset))

            abductor_hoverdown_offset = find_offset(
                page_data,
                "\\x80\\x88.{4}\\x02\\xc6\\x05.{4}\\x00\\xc6\\x05.{4}\\x00\\x31\\xc0\\xe8.{4}\\x80\\x3d.{4}\\x00\\x74\\x1e\\xe8.{4}\\xba\\x01\\x00\\x00\\x00\\xb8\\x05\\x00\\x00\\x00",
                0,
                "Alien Abductor hover-down button",
            )
            abductor_hoverdown_instrs = assemble_x86(
                [
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                    Instruction.create(Code.NOPD),
                ]
            )
            CODE_PATCHES.append((abductor_hoverdown_instrs, abductor_hoverdown_offset))

    if name == "Under a Killing Moon":
        try:
            credit_offset = find_offset(
                page_data, "and developed by", 0, "opening credits"
            )
            credit_data = b"(c) 1993.        \rMouselook v1.2 (c) 2025 moralrecordings.    \r                                "
            DATA_PATCHES.append((credit_data, credit_offset))
        except DataNotFound:
            pass

    # Apply the code patches, change the fixup table to match
    CODE_OBJ = 0
    DATA_OBJ = 2
    for mod_code, mod_offset in CODE_PATCHES:
        # print("Fixups to remove:")
        PATCH_RANGE = (mod_offset, mod_offset + len(mod_code))
        for i in range(len(fixup_records)):
            page_offset = i * le_header.page_size
            if (
                page_offset >= PATCH_RANGE[1]
                or (page_offset + le_header.page_size) < PATCH_RANGE[0]
            ):
                continue
            to_remove = []
            for j, record in enumerate(fixup_records[i]):
                src_addr = record.srcoff + page_offset
                if src_addr in range(PATCH_RANGE[0], PATCH_RANGE[1]):
                    # print((i, j, hex(src_addr), record))
                    to_remove.append(j)
            to_remove.reverse()
            for j in to_remove:
                fixup_records[i].pop(j)
        # print("Fixups to add:")
        decoder = Decoder(32, mod_code)
        for instr in decoder:
            # print((instr, instr.code))
            offset = mod_offset + instr.ip
            code = instr.code
            srcoff = offset % le_header.page_size
            page = offset // le_header.page_size
            # this is incomplete, there's hundreds of instructions in x86 which access memory.
            # I'm just adding them when I need them
            match code:
                case (
                    Code.ADD_RM32_R32
                    | Code.MOV_RM32_IMM32
                    | Code.AND_R8_RM8
                    | Code.TEST_RM8_IMM8
                    | Code.CMP_R32_RM32
                    | Code.CMP_RM8_IMM8
                    | Code.MOV_R8_RM8
                    | Code.MOV_R32_RM32
                    | Code.ADD_R32_RM32
                    | Code.AND_RM8_IMM8
                ):
                    fixup = FixupTuple(
                        "fix_32off_32",
                        0x7,
                        0x10,
                        DATA_OBJ,
                        srcoff + 2,
                        utils.from_uint32_le(mod_code[instr.ip + 2 : instr.ip + 6]),
                    )
                    # print((page, None, hex(offset), fixup))
                    fixup_records[page].append(fixup)
                case Code.MOV_RM32_R32 | Code.SUB_RM32_R32:
                    # this bastard can have both memory and registers as a source operand
                    if instr.memory_displacement:
                        fixup = FixupTuple(
                            "fix_32off_32",
                            0x7,
                            0x10,
                            DATA_OBJ,
                            srcoff + 2,
                            utils.from_uint32_le(mod_code[instr.ip + 2 : instr.ip + 6]),
                        )
                        # print((page, None, hex(offset), fixup))
                        fixup_records[page].append(fixup)
                case Code.MOV_AL_MOFFS8 | Code.MOV_MOFFS32_EAX | Code.MOV_EAX_MOFFS32:
                    fixup = FixupTuple(
                        "fix_32off_32",
                        0x7,
                        0x10,
                        DATA_OBJ,
                        srcoff + 1,
                        utils.from_uint32_le(mod_code[instr.ip + 1 : instr.ip + 5]),
                    )
                    # print((page, None, hex(offset), fixup))
                    fixup_records[page].append(fixup)
                case Code.MOV_RM16_IMM16:
                    fixup = FixupTuple(
                        "fix_32off_32",
                        0x7,
                        0x10,
                        DATA_OBJ,
                        srcoff + 3,
                        utils.from_uint32_le(mod_code[instr.ip + 3 : instr.ip + 7]),
                    )
                    # print((page, None, hex(offset), fixup))
                    fixup_records[page].append(fixup)
                case Code.JMP_RM32:
                    fixup = FixupTuple(
                        "fix_32off_32",
                        0x7,
                        0x10,
                        CODE_OBJ,
                        srcoff + 3,
                        utils.from_uint32_le(mod_code[instr.ip + 3 : instr.ip + 7]),
                    )
                    # print((page, None, hex(offset), fixup))
                    fixup_records[page].append(fixup)

        page_data[mod_offset : mod_offset + len(mod_code)] = mod_code

    for mod_data, mod_offset in DATA_PATCHES:
        page_data[mod_offset : mod_offset + len(mod_data)] = mod_data

    # Finally, write the output file with our changes
    with open(output, "wb") as out:
        fixup_output = [fixups_encode(x) for x in fixup_records]
        fixup_page_table.offsets = []
        acc = 0
        for x in fixup_output:
            fixup_page_table.offsets.append(acc)
            acc += len(x)
        fixup_page_table.offsets.append(acc)
        fixup_page_table_output = fixup_page_table.export_data()
        fixup_record_table_output = b"".join(fixup_output)

        post_fixup_start = le_header.import_module_table_offset
        post_fixup_end = mz_off + le_header.data_pages_offset - le_off
        post_fixup_blob = f[le_off + post_fixup_start : le_off + post_fixup_end]

        le_header.fixup_record_table_offset = le_header.fixup_page_table_offset + len(
            fixup_page_table_output
        )
        le_header.fixup_section_size = len(fixup_page_table_output) + len(
            fixup_record_table_output
        )
        le_header.fixup_section_csum = 0

        le_header.import_module_table_offset = (
            le_header.fixup_page_table_offset + le_header.fixup_section_size
        )
        le_header.import_proc_table_offset = le_header.import_module_table_offset
        le_header.data_pages_offset = (
            le_off
            + le_header.import_module_table_offset
            + len(post_fixup_blob)
            - mz_off
        )

        out.write(f[:le_off])
        out.write(le_header.export_data())
        header_size = le_header.get_size()
        out.write(f[le_off + header_size : le_off + le_header.fixup_page_table_offset])
        out.write(fixup_page_table_output)
        out.write(fixup_record_table_output)
        out.write(post_fixup_blob)
        out.write(page_data)

    print(f"Finished patching {name} v{version}, {language.title()} language")
