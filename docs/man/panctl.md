PANCTL(1) - General Commands Manual

# NAME

**panctl** - Control the Matrix reverse proxy daemon pantalaimon.

# DESCRIPTION

**panctl**
is a small utility to control and introspect the state of pantalaimon.

## Commands

The commands accepted by
**panctl**
are as follows:

**list-servers**

> List the configured homeservers and pan users on each homeserver.

**list-devices** *pan-user* *user-id*

> List the devices of a user that are known to the
> *pan-user*.

**start-verification** *pan-user* *user-id*

> Start an interactive key verification between the given pan-user and user.

**accept-verification** *pan-user* *user-id*

> Accept an interactive key verification that the given user has started with our
> given pan-user.

**cancel-verification** *pan-user* *user-id*

> Cancel an interactive key verification between the given pan-user and user.

**confirm-verification** *pan-user* *user-id*

> Confirm that the short authentication string of the interactive key verification
> with the given pan-user and user is matching.

**verify-device** *pan-user* *user-id* *device-id*

> Manually mark the given device as verified. The device will be marked as verified
> only for the given pan-user.

**unverify-device** *pan-user* *user-id* *device-id*

> Mark a previously verified device of the given user as unverified.

**blacklist-device** *pan-user* *user-id* *device-id*

> Manually mark the given device of the given user as blacklisted.

**unblacklist-device** *pan-user* *user-id* *device-id*

> Mark a previously blacklisted device of the given user as unblacklisted.

**send-anyways** *pan-user* *room-id*

> If a encrypted room contains unverified devices and a connected Matrix client
> tries to send an message to such a room
> **pantalaimon**
> will send a notification that the room contains unverified users. Using this
> command the user can choose to mark all unverified devices as ignored. Ignored
> devices will receive encryption keys but will be left marked as unverified.
> The message will be sent away after all devices are marked as ignored.

**cancel-sending** *pan-user* *room-id*

> In contrast to the
> **send-anyways**
> command this command cancels the sending of a message to an encrypted room with
> unverified devices and gives the user the oportunity to verify or blacklist
> devices as they see fit.

**import-keys** *pan-user* *file* *passphrase*

> Import end-to-end encryption keys from the given file for the given pan-user.

**export-keys** *pan-user* *file* *passphrase*

> Export end-to-end encryption keys to the given file for the given pan-user. The
> provided passphrase is used to encrypt the file containing the keys.

# EXIT STATUS

The **panctl** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# SEE ALSO

pantalaimon(8)
pantalaimon(5)

# AUTHORS

**panctl**
was written by
Damir Jeli&#263; &lt;[poljar@termina.org.uk](mailto:poljar@termina.org.uk)&gt;.

Linux 5.1.3-arch2-1-ARCH - May 23, 2019
