# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **BREAKING (XSY-0031):** Removed support for the legacy top-level `codex:`
  WORKFLOW.md block; loading now fails with a structured error. Use
  `runner: {kind: shell, preset: codex}` instead.
