# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
