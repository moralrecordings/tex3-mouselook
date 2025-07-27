Under a Killing Moon/The Pandora Directive - Mouselook Edition
==============================================================

Tex Murphy: Under a Killing Moon by Access Software is a fun game, with state of the art (for 1994!) 3D environments.

There is one small downside: the game was developed before first-person 3D controls were standardised, and features a truly unique control scheme. Instead of the mouse being used to adjust the player direction and head tilt, it's used to adjust forwards/backwards velocity and turning velocity. This is very awkward, and on DOSBox and Pentium systems the movement code runs too quickly.

While this may be an accurate walking simulation for a whiskey-soaked PI, it's a rough experience for players. All of the ingredients for a good control system are in the engine, so this mod patches the movement code and replaces the mad controls with the more common mouselook + WASD.

As it happens, the sequel The Pandora Directive uses near identical movement code! Sometimes it really is impossible to improve on perfection.

To apply the patches, you will need the `Xdelta patching tool <https://github.com/jmacd/xdelta-gpl/releases/tag/v3.1.0>`_. Windows users who are after a GUI tool might have luck with `Xdelta UI <https://www.romhacking.net/utilities/598>`_.

New keyboard controls 
---------------------
- **Mouse** - Look around
- **[W]** - forwards
- **[A]** - strafe left
- **[S]** - backwards
- **[D]** - strafe right
- **[C]** - crouch (while held)
- **[L-Shift]** - run (while held)

Applying the Under a Killing Moon patch
---------------------------------------

The patch is in VCDIFF format, and requires TEX3.EXE from the GOG.com edition of Under a Killing Moon (sha1: 6aa11ae0e6e763849dd7f44c18ce1987c6763665).

.. code:: bash

   xdelta3 -d -s tex3.exe tex3mod.vcdiff tex3mod.exe

As of July 2025, the GOG.com edition will try and run TEX197.EXE. If you want to use their bundled DOSBox to play the game, you will still need to build the patch using TEX3.EXE, but instead replace TEX197.EXE with the patched version, or edit ``dosboxTex3_single.conf`` to use the new EXE. The patched version is save-compatible with the original.

Applying the Pandora Directive patch
------------------------------------

The patch is in VCDIFF format, and requires TEX4.EXE from the GOG.com edition of The Pandora Directive (sha1: 6b47d8d202a1a0e8b9fd95e374aa71db0cf128c7)

.. code:: bash

   xdelta3 -d -s tex4.exe tex4mod.vcdiff tex4mod.exe

The GOG.com edition will try and run TEX4.EXE. If you want to use their bundled DOSBox to play the game, you will need to replace TEX4.EXE with the patched version, or edit ``dosboxTex4_single.conf`` to use the new EXE. The patched version is save-compatible with the original.
