# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
