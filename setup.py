from os import path

from setuptools import find_packages, setup

from tex3patch.version import __version__

# Get the long description from the README file
# here = path.abspath( path.dirname( __file__ ) )
# with open( path.join( here, "DESCRIPTION.rst" ), encoding="utf-8" ) as f:
#    long_description = f.read()

setup(
    name="tex3patch",
    version=__version__,
    description=("Under a Killing Moon/The Pandora Directive - Mouselook Edition"),
    license="GPL-3.0",
    author="Scott Percival",
    author_email="code@moral.net.au",
    python_requires=">=3",
    install_requires=[
        "typing_extensions",
        "mrcrowbar >= 1.0.0rc2",
        "iced_x86 >= 1.21.0",
    ],
    extras_require={},
    packages=["tex3patch"],
    entry_points={
        "console_scripts": [
            "tex3patch = tex3patch.cli:main",
        ],
    },
)
