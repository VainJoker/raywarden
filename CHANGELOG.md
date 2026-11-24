# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/VainJoker/raywarden/releases/tag/v0.1.1) - 2026-11-24

### Added

- [**breaking**] expand Worker APIs and establish the new D1 baseline ([#1](https://github.com/VainJoker/raywarden/pull/1))
- Fix known issues and add missing functionality
- Basic functionality completed, pending code refactor
- Add additional API implementations, reorganize the routing infrastructure
- initial Bitwarden-compatible backend API and core models

### Fixed

- Optimize attachment fast-path
- Modify 2fa login error response

### Other

- *(deps)* bump url from 2.5.8 to 2.5.9
- *(deps-dev)* bump wrangler from 4.163.0 to 4.166.0
- Move database operations to the model layer
- Modify the error-handling logic flow
- add deployment documentation for configuration
