# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

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
        "typing;python_version<'3.5'",
        "matrix-nio @ git+https://github.com/poljar/matrix-nio.git@async#egg=matrix-nio-0"
    ],
    entry_points={
        "console_scripts": ["pantalaimon=pantalaimon.daemon:main"],
    },
    zip_safe=False
)
