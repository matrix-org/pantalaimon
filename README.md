pantalaimon
===========

Pantalaimon is an end-to-end encryption aware Matrix reverse proxy daemon.
Pantalaimon acts as a good man in the middle that handles the encryption for you.

Messages are transparently encrypted and decrypted for clients inside of
pantalaimon.

![Pantalaimon in action](docs/pan.gif)

Installation
============

The [Olm](https://gitlab.matrix.org/matrix-org/olm) C library is required to
be installed before installing pantalaimon.

If your distribution provides packages for libolm it is best to use those, note
that a recent version of libolm is required (3.1+). If your distribution doesn't
provide a package building from source is required. Please refer to the Olm
[readme](https://gitlab.matrix.org/matrix-org/olm/blob/master/README.md)
to see how to build the C library from source.

Installing pantalaimon works like usually with python packages:

    python setup.py install

or you can use `pip` and install it with:
```
pip install .[ui]
```

Pantalaimon can also be found on pypi:

    pip install pantalaimon

Pantalaimon contains a dbus based UI that can be used to control the daemon.
The dbus based UI is completely optional and needs to be installed with the
daemon:

    pip install pantalaimon[ui]

Do note that man pages can't be installed with pip.

### macOS installation

For instance, on macOS, this means:

```bash
brew install dbus
perl -pi -e's#(<auth>EXTERNAL</auth>)#<!--$1-->#' $(brew --prefix dbus)/share/dbus-1/session.conf
brew services start dbus
# it may be necessary to restart now to get the whole OS to pick up the
# existence of the dbus daemon

git clone https://gitlab.matrix.org/matrix-org/olm
(cd olm; make)
git clone https://github.com/matrix-org/pantalaimon
(cd pantalaimon; CFLAGS=-I../olm/include LDFLAGS=-L../olm/build/ python3 setup.py install)

export DBUS_SESSION_BUS_ADDRESS=unix:path=$(launchctl getenv DBUS_LAUNCHD_SESSION_BUS_SOCKET)
cd pantalaimon
DYLD_LIBRARY_PATH=../olm/build/ pantalaimon -c contrib/pantalaimon.conf

# for notification center:
git clone https://github.com/fakechris/notification-daemon-mac-py
# if you have django's `foundation` library installed and your filesystem
# is case insensitive (the default) then you will need to `pip uninstall foundation`
# or install PyObjC in a venv...
pip install PyObjC daemon glib dbus-python
cd notification-daemon-mac-py
./notify.py
```

### Docker

An experimental Docker image can be built for Pantalaimon, primarily for use in bots.

```bash
docker build -t pantalaimon .
# Create a pantalaimon.conf before running. The directory mentioned in the
# volume below is for where Pantalaimon should dump some data.
docker run -it --rm -v /path/to/pantalaimon/dir:/data -p 8008:8008 pantalaimon
```
The Docker image in the above example can alternatively be built straight from any branch or tag without the need to clone the repo, just by using this syntax:
```bash
docker build -t pantalaimon github.com/matrix-org/pantalaimon#master
```

An example `pantalaimon.conf` for Docker is:
```conf
[Default]
LogLevel = Debug
SSL = True

[local-matrix]
Homeserver = https://matrix.org
ListenAddress = 0.0.0.0
ListenPort = 8008
SSL = False
UseKeyring = False
IgnoreVerification = True
```

Usage
=====

While pantalaimon is a daemon, it is meant to be run as the same user as the app it is proxying for. It won't
verify devices for you automatically, unless configured to do so, and requires
user interaction to verify, ignore or blacklist devices. A more complete
description of Pantalaimon can be found in the [man page](docs/man/pantalaimon.8.md).

Pantalaimon requires a configuration file to run. The configuration file
specifies one or more homeservers for pantalaimon to connect to.

A minimal pantalaimon configuration looks like this:
```dosini
[local-matrix]
Homeserver = https://localhost:443
ListenAddress = localhost
ListenPort = 8009
```

The configuration file should be placed in `~/.config/pantalaimon/pantalaimon.conf`.

The full documentation for the pantalaimons configuration can be found in
the [man page](docs/man/pantalaimon.5.md) `pantalaimon(5)`.

Now that pantalaimon is configured it can be run:

    pantalaimon --log-level debug

After running the daemon, configure your client to connect to the daemon instead
of your homeserver. The daemon listens by default on localhost and port 8009.

Note that logging in to the daemon is required to start a sync loop for a user.
After that clients can connect using any valid access token for the user that
logged in. Multiple users per homeserver are supported.

For convenience a systemd service file is provided.

To control the daemon an interactive utility is provided in the form of
`panctl`.

`panctl` can be used to verify, blacklist or ignore devices, import or export
session keys, or to introspect devices of users that we share encrypted rooms
with.

### Setup
This is all coming from an excellent comment that you can find [here](https://github.com/matrix-org/pantalaimon/issues/154#issuecomment-1951591191).



1) Ensure you have an OS keyring installed. In my case I installed `gnome-keyring`. You may also want a GUI like `seahorse` to inspect the keyring. (pantalaimon will work without a keyring but your client will have to log in with the password every time `pantalaimon` is restarted, instead of being able to reuse the access token from the previous successful login.)

2) In case you have prior attempts, clean the slate by deleting the `~/.local/share/pantalaimon` directory.

3) Start `pantalaimon`.

4) Connect a client to the `ListenAddress:ListenPort` you specified in `pantalaimon.conf`, eg to `127.0.0.1:8009`, using the same username and password you would've used to login to your homeserver directly.

5) The login should succeed, but at this point all encrypted messages will fail to decrypt. This is fine.

6) Start another client that you were already using for your encrypted chats previously. In my case this was `app.element.io`, so the rest of the steps here assume that.

7) Run `panctl`. At the prompt, run `start-verification <user ID> <user ID> <Element's device ID>`. `<user ID>` here is the full user ID like `@arnavion:arnavion.dev`. If you only have the one Element session, `panctl` will show you the device ID as an autocomplete hint so you don't have to look it up. If you do need to look it up, go to Element -> profile icon -> All Settings -> Sessions, expand the "Current session" item, and the "Session ID" is the device ID.

8) In Element you will see a popup "Incoming Verification Request". Click "Continue". It will change to a popup containing some emojis, and `panctl` will print the same emojis. Click the "They match" button. It will now change to a popup like "Waiting for other client to confirm..."

9) In `panctl`, run `confirm-verification <user ID> <user ID> <Element's device ID>`, ie the same command as before but with `confirm-verification` instead of `start-verification`.

10) At this point, if you look at all your sessions in Element (profile icon -> All Settings -> Sessions), you should see "pantalaimon" in the "Other sessions" list as a "Verified" session.

11) Export the E2E room keys that Element was using via profile icon -> Security & Privacy -> Export E2E room keys. Pick any password and then save the file to some path.

12) Back in `panctl`, run `import-keys <user ID> <path of file> <password you used to encrypt the file>`. After a few seconds, in the output of `pantalaimon`, you should see a log like `INFO: pantalaimon: Successfully imported keys for <user ID> from <path of file>`.

13) Close and restart the client you had used in step 5, ie the one you want to connect to `pantalaimon`. Now, finally, you should be able to see the encrypted chats be decrypted.

14) Delete the E2E room keys backup file from step 12. You don't need it any more.


15) If in step 11 you had other unverified sessions from pantalaimon from your prior attempts, you can sign out of them too.

You will probably have to repeat steps 11-14 any time you start a new encrypted chat in Element.
