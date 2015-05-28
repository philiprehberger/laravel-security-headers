<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | HTTP Strict Transport Security (HSTS)
    |--------------------------------------------------------------------------
    |
    | HSTS tells browsers to only communicate with your site over HTTPS.
    | Enable this only when your site is fully served over HTTPS.
    |
    */
    'hsts' => [
        'enabled' => env('SECURITY_HEADERS_HSTS', false),
        'max_age' => 31536000,
        'include_subdomains' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Security Policy (CSP)
    |--------------------------------------------------------------------------
    |
    | The CSP header helps prevent XSS attacks by controlling which resources
    | the browser is allowed to load. A nonce is generated per request and
    | shared with views so inline scripts can be authorised.
    |
    | Additional sources are merged with the hardened defaults for each
    | directive. Values must be valid CSP source expressions, e.g.:
    |   "'self'", "'unsafe-inline'", "https://example.com", "data:", etc.
    |
    */
    'csp' => [
        'enabled' => true,

        // Name of the Blade / View variable that holds the nonce
        'nonce_view_variable' => 'cspNonce',

        // Name of the Request attribute that holds the nonce
        'nonce_request_attribute' => 'csp_nonce',

        // Whether to include 'unsafe-eval' in script-src (default true for compatibility)
        'unsafe_eval' => true,

        // Whether to include 'unsafe-inline' in style-src (default true for compatibility)
        'unsafe_inline' => true,

        // Extra sources appended to script-src (nonce + 'self' + 'unsafe-eval' always included)
        'script_src' => [],

        // Extra sources appended to style-src ('self' + 'unsafe-inline' always included)
        'style_src' => [],

        // Extra sources appended to img-src ('self' + data: + blob: always included)
        'img_src' => [],

        // Extra sources appended to font-src ('self' + data: always included)
        'font_src' => [],

        // Extra sources appended to connect-src ('self' always included)
        'connect_src' => [],

        // frame-ancestors directive (replaces X-Frame-Options in modern browsers)
        'frame_ancestors' => ["'self'"],

        // form-action directive restricts where forms may submit
        'form_action' => ["'self'"],
    ],

    /*
    |--------------------------------------------------------------------------
    | Standard Security Headers
    |--------------------------------------------------------------------------
    |
    | Set any of these to null to skip that header entirely.
    |
    */
    'x_content_type_options' => 'nosniff',

    'x_frame_options' => 'SAMEORIGIN',

    'x_xss_protection' => '1; mode=block',

    'referrer_policy' => 'strict-origin-when-cross-origin',

    'permissions_policy' => 'geolocation=(), camera=(), microphone=(), payment=()',

    /*
    |--------------------------------------------------------------------------
    | Vite Dev Server
    |--------------------------------------------------------------------------
    |
    | When enabled and the application is running in a local environment,
    | the Vite dev server origin is automatically added to script-src,
    | style-src, and connect-src (including ws:// variants).
    |
    */
    'vite' => [
        'enabled' => true,
        'dev_server' => 'http://127.0.0.1:5173',
    ],

];
