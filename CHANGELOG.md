# Changelog

All notable changes to `laravel-security-headers` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2026-03-31

### Changed
- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## [1.2.1] - 2026-03-23

### Changed
- Remove non-standard Features section from README per template guide

## [1.2.0] - 2026-03-22

### Added
- `CspDirective` backed string enum with cases for common CSP directive names
- `report_only` config option (default `false`) — when `true`, sends `Content-Security-Policy-Report-Only` header instead of `Content-Security-Policy`
- Tests for `CspDirective` enum values, Report-Only header output, and normal CSP header when `report_only` is disabled

## [1.1.7] - 2026-03-23

### Fixed
- Standardize CHANGELOG preamble to use package name

## [1.1.6] - 2026-03-21

### Changed
- Consolidate README and configuration updates from diverged branch

## [1.1.4] - 2026-03-17

### Fixed
- Add phpstan.neon configuration for CI static analysis

## [1.1.3] - 2026-03-17

### Changed
- Standardized package metadata, README structure, and CI workflow per package guide

## [1.1.2] - 2026-03-16

### Changed
- Standardize composer.json: add type, homepage, scripts
- Add Development section to README

## [1.1.1] - 2026-03-15

### Changed
- Add README badges

## [1.1.0] - 2026-03-12

### Added
- Configurable `unsafe_eval` option to toggle `'unsafe-eval'` in `script-src` (default `true`)
- Configurable `unsafe_inline` option to toggle `'unsafe-inline'` in `style-src` (default `true`)
- Documentation for hardcoded CSP directives (`default-src`, `base-uri`, `object-src`)
- 14 new tests covering CSP directive toggles, Vite dev server, frame-ancestors, form-action, style-src, font-src, HSTS options, base-uri, and object-src

## [1.0.0] - 2026-03-05

### Added
- `SecurityHeaders` middleware with per-request CSP nonce generation
- CSP nonce shared to all Blade views via `View::share`
- CSP nonce written to the request attributes bag for programmatic access
- Fully config-driven CSP directives: `script_src`, `style_src`, `img_src`, `font_src`, `connect_src`, `frame_ancestors`, `form_action`
- Configurable HSTS with `max_age` and `includeSubDomains` options (disabled by default)
- Configurable `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy` headers
- Setting any scalar header config value to `null` suppresses that header
- Vite dev server auto-detection: adds dev-server origin and its `ws://` variant to `script-src`, `style-src`, and `connect-src` when `APP_ENV=local`
- `SecurityHeadersServiceProvider` with config merging and publishable config asset
- Laravel auto-discovery via `extra.laravel` in `composer.json`
- PHPUnit 11 test suite covering all headers, nonce generation, HSTS toggle, custom sources, and null-disabling behaviour
