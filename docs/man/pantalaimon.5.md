PANTALAIMON.CONF(5) - File Formats Manual

# NAME

**pantalaimon.conf** - pantalaimon configuration file

# DESCRIPTION

pantalaimon(1) reads configuration data in the INI file format.
The configuration file is used to configure
**pantalaimon**
homeservers.

The sections inside the configuration file represent a pantalaimon proxy
instance with the section name enclosed in square brackets representing an user
chosen instance name.

The following keys are required in the proxy instance sections:

**Homeserver**

> The URI of the homeserver that the pantalaimon proxy should forward requests to,
> without the matrix API path but including the http(s) schema.

The following keys are optional in the proxy instance sections:

**ListenAddress**

> The address where the daemon will listen to client connections for this
> homeserver. Defaults to "localhost".

**ListenPort**

> The port where the daemon will listen to client connections for this
> homeserver. Note that the listen address/port combination needs to be unique
> between different homeservers. Defaults to "8009".

**Proxy**

> An URI of a HTTP proxy that the daemon should use when making requests to the
> homeserver.
> **pantalaimon**
> only supports HTTP proxies. The default is to make a direct connection to the
> homeserver.

**SSL**

> A boolean that decides if SSL verification should be enabled for outgoing
> connections to the homeserver. Defaults to "True".

**IgnoreVerification**

> A boolean that decides if device verification should be enabled. If this is True
> devices will be marked as ignored automatically and encryption keys will be
> shared with them, if this is False the user needs to verify, blacklist or ignore
> devices manually before messages can be sent to a room. Defaults to "False".

**UseKeyring**

> This option configures if a proxy instance should use the OS keyring to store
> its own access tokens. The access tokens are required for the daemon to resume
> operation. If this is set to "No", access tokens are stored in the pantalaimon
> database in plaintext. Defaults to "Yes".

**DropOldKeys**

> This option configures if a proxy instance should only keep the latest version
> of a room key from a certain user around. This effectively means that only newly
> incoming messages will be decryptable, the proxy will be unable to decrypt the
> room history.  Defaults to "No".

**ClientMaxSize**

> The maximum size of a request, in bytes. Defaults to "104857600".

Additional to the homeserver section a special section with the name
**Default**
can be used to configure the following values for all homeservers:
**ListenAddress**,
**ListenPort**,
**Proxy**,
**SSL**
**IgnoreVerification**
**UseKeyring**

The
**Default**
section has the following keys that globally change the behaviour of the daemon:

**LogLevel**

> Set the log level of the daemon, can be one of
> *error*,
> *warning*,
> *info*,
> *debug*.
> Defaults to
> *warning*.

**Notifications**

> The daemon sends out notifications for some actions that require users to
> interfere (unverified devices are in a room, interactive key verification
> events), this option enables or disables OS notifications. Can be one of
> *On*,
> *Off*.
> Defaults to
> *On*.

# FILES

**pantalaimon**
supports the XDG Base Directory Specification, the default locations can be
overridden using appropriate environment variables.

*~/.config/pantalaimon/pantalaimon.conf*

> Default location of the configuration file.

# EXAMPLES

The following example shows a configured pantalaimon proxy with the name
*Clocktown*,
the homeserver URL is set to
*https://localhost:8448*,
the pantalaimon proxy is listening for client connections on the address
*localhost*,
and port
*8009*.
The pantalaimon proxy is making connections to the homeserver through the proxy
*http://localhost:8009*,
finally, SSL verification is disabled.

Additionally to the
*Clocktown*
section the
*Default*
section is also listed and the default value for SSL verification is set to
True, OS notifications are enabled and the debug level is set to
*Debug*.

	[Default]
	LogLevel = Debug
	SSL = True
	Notifications = On
	
	[Clocktown]
	Homeserver = https://localhost:8448
	ListenAddress = localhost
	ListenPort = 8009
	Proxy = http://localhost:8080
	SSL = False

# SEE ALSO

pantalaimon(8)

# AUTHORS

**pantalaimon.conf**
was written by
Damir Jeli&#263; &lt;[poljar@termina.org.uk](mailto:poljar@termina.org.uk)&gt;.

Linux 5.11.16-arch1-1 - May 8, 2019
