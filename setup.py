# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pantalaimon",
    version="0.5.1",
    url="https://github.com/matrix-org/pantalaimon",
    author="The Matrix.org Team",
    author_email="poljar@termina.org.uk",
    description=("A Matrix proxy daemon that adds E2E encryption "
                 "capabilities."),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache License, Version 2.0",
    packages=find_packages(),
    install_requires=[
        "attrs",
        "aiohttp",
        "appdirs",
        "click",
        "keyring",
        "logbook",
        "peewee",
        "janus",
        "cachetools >= 3.0.0"
        "prompt_toolkit>2<4",
        "typing;python_version<'3.5'",
        "matrix-nio[e2e] >= 0.8.0"
    ],
    extras_require={
        "ui": [
            "dbus-python",
            "PyGObject",
            "pydbus",
            "notify2",
        ]
    },
    entry_points={
        "console_scripts": ["pantalaimon=pantalaimon.main:main",
                            "panctl=pantalaimon.panctl:main"],
    },
    zip_safe=False
)
