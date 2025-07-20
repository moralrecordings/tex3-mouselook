Under a Killing Moon - Mouselook Edition
========================================

Under a Killing Moon by Access Software is a fun game, with state of the art (for 1994!) 3D environments.

There is one small downside: the game was developed before first-person 3D controls were standardised, and features a truly unique control scheme. Instead of the mouse being used to adjust the player direction and head tilt, it's used to adjust forwards/backwards velocity and turning velocity. This is very awkward, and on DOSBox and Pentium systems the movement code runs too quickly.

While this may be an accurate walking simulation for a whiskey-soaked PI, it's a rough experience for players. All of the ingredients for a good control system are in the engine, so this mod patches the movement code and replaces the mad controls with the more common mouselook + WASD.

New keyboard controls 
---------------------
- **Mouse** - Look around
- **[W]** - forwards
- **[A]** - strafe left
- **[S]** - backwards
- **[D]** - strafe right
- **[C]** - crouch (while held)
- **[L-Shift]** - run (while held)

Applying the patch
------------------

The patch is in VCDIFF format, and requires TEX3.EXE from the GOG.com edition of Under a Killing Moon (sha1: 6aa11ae0e6e763849dd7f44c18ce1987c6763665).

.. code:: bash

   xdelta3 -d -s tex3.exe texmod.vcdiff texmod.exe


