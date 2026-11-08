# Changelog

All notable changes to keyrings.prego are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `keyrings.prego` 0.1.0: a keyring backend that runs `prego token --python --url <url>` for Prego Python
  hosts only and never stores a token. Built and tested in CI. Not published to pypi.org yet.
- A plain `http://` URL gets no token, except for a loopback host.
