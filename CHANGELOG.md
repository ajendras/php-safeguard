# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-06

### Added

- AST Analysis — Uses nikic/php-parser to detect unsanitized sinks for SQLi, XSS, and command injection.
- Dependency Audit — Cross-references composer.lock against the GitHub Advisory Database for vulnerable packages.
- Laravel Rules — Catches mass assignment, missing validation, route model binding issues and more.
- Rich Reports — Color-coded terminal output, JSON, or SARIF with exact line numbers and remediation code.
- Safe Auto-Fix — Automatically wraps echo with htmlspecialchars and adds missing security headers when --fix is used.
- Configurable Rules — YAML-based rule toggles and severity thresholds per project via .safeguard.yml.
- CI Optimized — Non-zero exit codes on high-severity findings; designed for GitHub Actions workflows.
- Severity Scoring — CVSS-inspired scoring with ignore directives for accepted risks.
