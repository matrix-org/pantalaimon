# -*- coding: utf-8 -*-

from setuptools import find_packages, setup
import os

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()


def get_manpages():
    """
    This function goes and gets all the man pages so they can be installed when
    the package is installed.
    """
    man_pages = []
    for root, _, files in os.walk("docs/man"):
        for file in files:
            if file.endswith((".1", ".5", ".8")):
                man_section = file.split(".")[-1]
                dest_dir = os.path.join("share", "man", f"man{man_section}")
                man_pages.append((dest_dir, [os.path.join(root, file)]))
    return man_pages


setup(
    name="pantalaimon",
    version="0.10.5",
    url="https://github.com/matrix-org/pantalaimon",
    author="The Matrix.org Team",
    author_email="poljar@termina.org.uk",
    description=("A Matrix proxy daemon that adds E2E encryption capabilities."),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache License, Version 2.0",
    packages=find_packages(),
    install_requires=[
        "attrs >= 19.3.0",
        "aiohttp >= 3.6, < 4.0",
        "platformdirs >= 4.3.6",
        "click >= 7.1.2",
        "keyring >= 21.2.1",
        "logbook >= 1.5.3",
        "peewee >= 3.13.1",
        "janus >= 0.5",
        "cachetools >= 3.0.0",
        "prompt_toolkit > 2, < 4",
        "typing;python_version<'3.5'",
        "matrix-nio[e2e] >= 0.24, < 0.25.2",
    ],
    extras_require={
        "ui": [
            "dbus-python >= 1.2, < 1.3",
            "PyGObject >= 3.46, < 3.50",
            "pydbus >= 0.6, < 0.7",
            "notify2 >= 0.3, < 0.4",
        ]
    },
    entry_points={
        "console_scripts": [
            "pantalaimon=pantalaimon.main:main",
            "panctl=pantalaimon.panctl:main",
        ],
    },
    zip_safe=False,
    data_files=get_manpages(),
)
