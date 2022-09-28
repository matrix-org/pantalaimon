# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.10.5 2022-09-28

### Added

- [[#137]] Proxy the v3 endpoints as well

### Fixed

- [[#130]] Make sure the token variable is declared

[#137]: https://github.com/matrix-org/pantalaimon/pull/137
[#130]: https://github.com/matrix-org/pantalaimon/pull/130

## 0.10.4 2022-02-04

### Fixed

- [[#122]] Fix the GLib import for panctl on some distributions
- [[#120]] Don't use strip to filter Bearer from the auth header
- [[#118]] Don't use the raw path if we need to sanitize filters, fixing room
  history fetching for Fractal

[#122]: https://github.com/matrix-org/pantalaimon/pull/122
[#120]: https://github.com/matrix-org/pantalaimon/pull/120
[#118]: https://github.com/matrix-org/pantalaimon/pull/118

## 0.10.3 2021-09-02

### Fixed

- [[#105]] Use the raw_path when forwarding requests, avoiding URL
  decoding/encoding issues.

[#105]: https://github.com/matrix-org/pantalaimon/pull/105


## 0.10.2 2021-07-14

### Fixed

- [[#103]] Prevent E2EE downgrade on failed syncs

[#103]: https://github.com/matrix-org/pantalaimon/pull/103


## 0.10.1 2021-07-06

### Fixed

- [[#100]] Don't require the rooms dicts in the sync response
- [[#99]] Thumbnails not generating for media uploaded in unencrypted rooms
  whole LRU cache when it shouldn't

[#100]: https://github.com/matrix-org/pantalaimon/pull/100
[#99]: https://github.com/matrix-org/pantalaimon/pull/99


## 0.10.0 2021-05-14

### Added

- [[#98]] Add the ability to remove old room keys
- [[#95]] Encrypt thumbnails uploaded by a client

### Fixed

- [[#96]] Split out the media cache loading logic to avoid returning the
  whole LRU cache when it shouldn't

[#98]: https://github.com/matrix-org/pantalaimon/pull/98
[#96]: https://github.com/matrix-org/pantalaimon/pull/96
[#95]: https://github.com/matrix-org/pantalaimon/pull/95

## 0.9.3 2021-05-14

### Changed

- [[#73f68c7]] Bump the allowed nio version

[73f68c7]: https://github.com/matrix-org/pantalaimon/commit/73f68c76fb05037bd7fe71688ce39eb1f526a385

## 0.9.2 2021-03-10

### Changed

- [[#89]] Bump the allowed nio version

[#89]: https://github.com/matrix-org/pantalaimon/pull/89

## 0.9.1 2021-01-19

### Changed

- [[3baae08]] Bump the allowed nio version

[3baae08]: https://github.com/matrix-org/pantalaimon/commit/3baae08ac36e258632e224b655e177a765a939f3

## 0.9.0 2021-01-19

### Fixed

- [[59051c5]] Fix the notification initialization allowing the DBUS thread to
  start again

### Added

- [[#79]] Support media uploads, thanks to @aspacca

[59051c5]: https://github.com/matrix-org/pantalaimon/commit/59051c530a343a6887ea0f9ccddd6f6964f6d923
[#79]: https://github.com/matrix-org/pantalaimon/pull/79

## 0.8.0 2020-09-30

### Changed

- [[#69]] If no password is provided to /login, the daemon will re-use the original login response.

[#69]: https://github.com/matrix-org/pantalaimon/pull/69

## 0.7.0 2020-09-02

### Fixed

- [[#60]] Sanitize the GET /rooms/{room_id}/messages filters as well.
- [[#62]] Store media info when decrypting instead of using a event callback.

### Changed

- [[d425e2d]] Increase the max POST size.

[#62]: https://github.com/matrix-org/pantalaimon/pull/62
[#60]: https://github.com/matrix-org/pantalaimon/pull/60
[d425e2d]: https://github.com/matrix-org/pantalaimon/commit/d425e2d188aed32c3fe87cac210c0943fd51b085

## 0.6.5 2020-07-02

### Fixed

- [[a1ce950]] Allow to send messages using a POST request since Synapse seems to
  allow it.

[a1ce950]: https://github.com/matrix-org/pantalaimon/commit/a1ce95076ecd80c880028691feeced8d28cacad9

## 0.6.4 2020-06-21

### Changed
- Bump the maximal supported nio version.

## 0.6.3 2020-05-28

### Fixed
- Fix our dep requirements to avoid incompatibilities between nio and pantalaimon.

## 0.6.2 2020-05-27

### Fixed
- Don't require exact patch versions for our deps.

## 0.6.1 2020-05-12

### Fixed
- Bump the version to trigger a docker hub build with the latest nio release.

## 0.6.0 2020-05-10

### Added
- Add support for Janus 0.5.0.
- Added media endpoint handling to the /media/v1 path.

### Fixed
- Modify media events so they contain the unencrypted URL fields as well.
