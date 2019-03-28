pantalaimon
===========

A E2E aware matrix proxy daemon.

This still in an early development phase.

Instalation
===========

The [Olm](https://git.matrix.org/git/olm/) C library is required to be installed
before installing pantalaimon.

Instalation works like usually with python packages:

    python setup.py install

Usage
=====

Running the daemon is relatively easy:

    pantalaimon https://example.org:443

After running the daemon configure your client to connect to the daemon instead
of your homeserver. The daemon listens by default on localhost and port 8009.

The listening address and port can be configured:

    pantalaimon -l 127.0.0.1 -p 8008 https://example.org:8008
