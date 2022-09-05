PANTALAIMON(8) - System Manager's Manual

# NAME

**pantalaimon** - End-to-end encryption aware Matrix reverse proxy daemon.

# SYNOPSIS

**pantalaimon**
\[**-c**&nbsp;*config*]
\[**--log-level**&nbsp;*level*]
\[**--data-path**&nbsp;*path*]
\[**--version**]
\[**--help**]

# DESCRIPTION

**pantalaimon**
is a daemon that acts as a reverse proxy between a Matrix homeserver and a
Matrix client. The daemon transparently handles end-to-end encryption tasks on
behalf of the client.

**pantalaimon**
is supposed to run as your own user and listen to connections on a
non-privileged port. A client needs to log in using the standard Matrix HTTP
calls to register itself to the daemon, such a registered user is called a pan
user and will have its own sync loop to keep up with the server. Multiple matrix
clients can connect and use the same pan user.

If user interaction is required
**pantalaimon**
will send out OS notifications which the user can react to.
**pantalaimon**
also provides a D-Bus API that is used for encryption related tasks that
require user interference (e.g. device verification).

**pantalaimon**
requires a homeserver to be configured. Multiple homeservers can be configured,
each configured homeserver needs to listen on a separate port. Each homeserver
can handle end-to-end encryption for multiple users. The configuration file
format is specified in
pantalaimon(5),
the default location of the configuration file can be found in the
*FILES*
section.

## Options

The command line flags to change the behaviour of
**pantalaimon**
are as follows:

**-c**, **--config** *file*

> Use the supplied
> *file*
> as the configuration file instead of the default one.

**--log-level** *level*

> Set the log level of the daemon, can be one of
> *error*,
> *warning*,
> *info*,
> *debug*.
> Defaults to
> *warning*.

**--data-path** *path*

> Set the directory for the pantalaimon database. This config option takes
> precedence over the XDG environment variables.

**--version**

> Display the version number and exit.

**--help**

> Display the help and exit.

# FILES

**pantalaimon**
supports the XDG Base Directory Specification, the default locations can be
overridden using appropriate environment variables.

*~/.config/pantalaimon/pantalaimon.conf*

> Default location of the configuration file.
> The format of the configuration file is described in
> pantalaimon(5).

*~/.local/share/pantalaimon/pan.db*

> Default location of the pantalaimon database.
> This file is used to store a sqlite database holding daemon state and encryption
> keys.

# EXIT STATUS

The **pantalaimon** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# SEE ALSO

panctl(1)
pantalaimon(5)

# AUTHORS

**pantalaimon**
was written by
Damir Jeli&#263; &lt;[poljar@termina.org.uk](mailto:poljar@termina.org.uk)&gt;.

Linux 5.3.5-arch1-1-ARCH - October 18, 2019
