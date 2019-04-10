# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

setup(
    name="pantalaimon",
    version="0.1",
    url="https://github.com/matrix-org/pantalaimon",
    author="The Matrix.org Team",
    author_email="poljar@termina.org.uk",
    description=("A Matrix proxy daemon that adds E2E encryption "
                 "capabilities."),
    license="Apache License, Version 2.0",
    packages=find_packages(),
    install_requires=[
        "attrs",
        "aiohttp",
        "appdirs",
        "click",
        "logbook",
        "peewee",
        "typing;python_version<'3.5'",
        "matrix-nio"
    ],
    entry_points={
        "console_scripts": ["pantalaimon=pantalaimon.daemon:main"],
    },
    zip_safe=False
)
