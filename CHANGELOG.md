# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/VainJoker/raywarden/compare/v0.1.2...v0.1.3) - 2026-11-26

### Other

- simplify server architecture and harden error handling

## [0.1.2](https://github.com/VainJoker/raywarden/compare/v0.1.1...v0.1.2) - 2026-11-24

### Fixed

- *(auth)* handle Workers PBKDF2 iteration limit

## [0.1.1](https://github.com/VainJoker/raywarden/releases/tag/v0.1.1) - 2026-11-24

### Added

- [**breaking**] expand Worker APIs and establish the new D1 baseline ([#1](https://github.com/VainJoker/raywarden/pull/1))
- Fix known issues and add missing functionality
- Basic functionality completed, pending code refactor
- Add additional API implementations, reorganize the routing infrastructure
- initial Bitwarden-compatible backend API and core models

### Fixed

- *(ci)* trigger Cloudflare deployment directly on version tags
- Optimize attachment fast-path
- Modify 2fa login error response

### Other

- consolidate suites by business responsibility
- Merge pull request #3 from VainJoker/dependabot/github_actions/actions/download-artifact-8
- Merge pull request #4 from VainJoker/dependabot/github_actions/actions/upload-artifact-7
- *(deps)* bump url from 2.5.8 to 2.5.9
- *(deps-dev)* bump wrangler from 4.163.0 to 4.166.0
- *(deps)* bump actions/checkout from 6.0.2 to 7.0.1
- *(deps)* bump actions/upload-artifact from 6 to 7
- *(deps)* bump actions/download-artifact from 7 to 8
- Move database operations to the model layer
- Modify the error-handling logic flow
- add deployment documentation for configuration
