# Laravel Security Headers

A Laravel middleware package that adds a comprehensive set of HTTP security headers to every response, including a per-request CSP nonce, HSTS, and Permissions-Policy.

## Features

- Per-request CSP nonce — generated automatically and shared with all Blade views
- Content Security Policy built entirely from config arrays, no code changes required
- Configurable HSTS with `max_age` and `includeSubDomains`
- `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`
- Vite dev-server auto-detection adds the HMR origin and WebSocket URLs to the CSP when `APP_ENV=local`
- Any header can be suppressed by setting its config value to `null`
- Laravel 11 and 12 support, PHP 8.2+

## Installation

```bash
composer require philiprehberger/laravel-security-headers
```

Laravel auto-discovery registers the service provider automatically.

## Publishing the Config

```bash
php artisan vendor:publish --tag=security-headers-config
```

This copies `config/security-headers.php` into your application's `config/` directory.

## Registering the Middleware

### Laravel 11+ (bootstrap/app.php)

```php
use PhilipRehberger\SecurityHeaders\SecurityHeaders;

->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        SecurityHeaders::class,
    ]);
})
```

### Laravel 10 and earlier (app/Http/Kernel.php)

```php
protected $middlewareGroups = [
    'web' => [
        // ...
        \PhilipRehberger\SecurityHeaders\SecurityHeaders::class,
    ],
];
```

## Using the CSP Nonce in Blade

The nonce is shared to every view under the variable name configured in `csp.nonce_view_variable` (default: `cspNonce`).

```blade
<script nonce="{{ $cspNonce }}">
    console.log('Inline script allowed by CSP nonce');
</script>

<style nonce="{{ $cspNonce }}">
    /* Inline styles allowed by CSP nonce */
</style>
```

### Accessing the Nonce in PHP

```php
$nonce = $request->attributes->get('csp_nonce');
```

## Configuration Reference

```php
// config/security-headers.php

return [

    'hsts' => [
        // Set SECURITY_HEADERS_HSTS=true in .env (only when fully on HTTPS)
        'enabled'            => env('SECURITY_HEADERS_HSTS', false),
        'max_age'            => 31536000,
        'include_subdomains' => true,
    ],

    'csp' => [
        'enabled'                 => true,
        'nonce_view_variable'     => 'cspNonce',
        'nonce_request_attribute' => 'csp_nonce',

        // Extra sources merged into each directive
        'script_src'   => [],   // appended to: 'self' 'nonce-...' 'unsafe-eval'
        'style_src'    => [],   // appended to: 'self' 'unsafe-inline'
        'img_src'      => [],   // appended to: 'self' data: blob:
        'font_src'     => [],   // appended to: 'self' data:
        'connect_src'  => [],   // appended to: 'self'
        'frame_ancestors' => ["'self'"],
        'form_action'     => ["'self'"],
    ],

    // Set to null to omit the header entirely
    'x_content_type_options' => 'nosniff',
    'x_frame_options'        => 'SAMEORIGIN',
    'x_xss_protection'       => '1; mode=block',
    'referrer_policy'        => 'strict-origin-when-cross-origin',
    'permissions_policy'     => 'geolocation=(), camera=(), microphone=(), payment=()',

    'vite' => [
        'enabled'    => true,
        'dev_server' => 'http://127.0.0.1:5173',
    ],

];
```

## Customization Examples

### Allow an external CDN for scripts

```php
'csp' => [
    'script_src' => ['https://cdn.jsdelivr.net'],
],
```

### Allow external font providers

```php
'csp' => [
    'font_src'  => ['https://fonts.bunny.net', 'https://fonts.gstatic.com'],
    'style_src' => ['https://fonts.bunny.net'],
],
```

### Allow WebSocket connections to a production server

```php
'csp' => [
    'connect_src' => ['wss://ws.example.com'],
],
```

### Allow forms to post to a subdomain

```php
'csp' => [
    'form_action' => ["'self'", 'https://portal.example.com'],
],
```

### Enable HSTS in production via environment variable

```env
SECURITY_HEADERS_HSTS=true
```

### Remove a header you do not need

```php
'x_xss_protection' => null,
```

## Running the Tests

```bash
composer install
vendor/bin/phpunit
```

## License

MIT License. Copyright (c) 2026 [Philip Rehberger](mailto:me@philiprehberger.com).
