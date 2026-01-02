Under a Killing Moon/The Pandora Directive - Mouselook Edition
==============================================================

Tex Murphy: Under a Killing Moon by Access Software is a fun game, with state of the art (for 1994!) 3D environments.

There is one small downside: the game was developed before first-person 3D controls were standardised, and features a truly unique control scheme. Instead of the mouse being used to adjust the player direction and head tilt, it's used to adjust forwards/backwards velocity and turning velocity. This is very awkward, and on DOSBox and Pentium systems the movement code runs too quickly.

While this may be an accurate walking simulation for a whiskey-soaked PI, it's a rough experience for players. All of the ingredients for a good control system are in the engine, so this mod patches the movement code and replaces the mad controls with the more common mouselook + WASD.

As it happens, the sequel The Pandora Directive uses near identical movement code! Sometimes it really is impossible to improve on perfection.

This repository contains the Python command-line tool for applying the patch to TEX3.EXE or TEX4.EXE - for normal usage we recommend trying the `browser-based version <https://moralrecordings.itch.io/tex3-mouselook>`_.

Compatibility
-------------

This tool should work for all versions and language editions of Under a Killing Moon and The Pandora Directive. The patcher is dynamic - that is, it will try and read the executable, find the correct functions and variables based on code fragments, then inject the correct modifications.

If you are using the GOG.COM edition of Under a Killing Moon, be aware that it uses TEX197.EXE as the game executable; you will probably want to patch this instead of TEX3.EXE.

New keyboard controls 
---------------------
- **Mouse** - Look around
- **[W]** - forwards
- **[A]** - strafe left
- **[S]** - backwards
- **[D]** - strafe right
- **[C]** - crouch (while held)
- **[R]** - reach up on tippytoes (while held)
- **[L-Shift]** - run (while held)

Version history
---------------

- v1.2 - 2026-01-02 - Rewrote the patching tool to be dynamic, add mouse invert-y
- v1.1 - 2025-08-24 - Improved screen flickering, fixed Alien Abductor in tex4
- v1.0 - 2025-08-05 - Added reach control, fixed vertical mouselook clamping
- v0.9 - 2025-07-24 - Initial release
