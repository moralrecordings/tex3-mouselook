from __future__ import annotations

import argparse
import pathlib
import sys

from .patch import patch
from .version import __version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Apply mods to Under a Killing Moon/The Pandora Directive"
    )
    parser.add_argument(
        "INPUT", type=pathlib.Path, help="Input file name, either tex3.exe or tex4.exe"
    )
    parser.add_argument("OUTPUT", type=pathlib.Path, help="Output file name")
    parser.add_argument(
        "--fix-speed",
        action="store_true",
        help="Fix bug where Tex rockets around in areas of low geometric complexity on Pentium/DOSBox.",
    )
    parser.add_argument(
        "--mouselook",
        action="store_true",
        help="Replace bonkers movement controls with WASD + mouselook.",
    )
    parser.add_argument(
        "--invert-y", action="store_true", help="Invert Y-axis movement for mouselook."
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit.",
    )
    args = parser.parse_args(argv or sys.argv[1:])
    patch(args.INPUT, args.OUTPUT, args.fix_speed, args.mouselook, args.invert_y)


if __name__ == "__main__":
    main()
