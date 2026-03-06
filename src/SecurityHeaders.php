<?php

declare(strict_types=1);

namespace PhilipRehberger\SecurityHeaders;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\View;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Generate a unique CSP nonce for this request
        $nonce = base64_encode(random_bytes(16));

        $nonceRequestAttr = config('security-headers.csp.nonce_request_attribute', 'csp_nonce');
        $nonceViewVar = config('security-headers.csp.nonce_view_variable', 'cspNonce');

        $request->attributes->set($nonceRequestAttr, $nonce);
        View::share($nonceViewVar, $nonce);

        $response = $next($request);

        // Strict Transport Security (HSTS)
        if (config('security-headers.hsts.enabled', false)) {
            $maxAge = (int) config('security-headers.hsts.max_age', 31536000);
            $hsts = "max-age={$maxAge}";

            if (config('security-headers.hsts.include_subdomains', true)) {
                $hsts .= '; includeSubDomains';
            }

            $response->headers->set('Strict-Transport-Security', $hsts);
        }

        // Content Security Policy
        if (config('security-headers.csp.enabled', true)) {
            $response->headers->set('Content-Security-Policy', $this->buildCsp($nonce));
        }

        // X-Content-Type-Options
        if (($value = config('security-headers.x_content_type_options')) !== null) {
            $response->headers->set('X-Content-Type-Options', $value);
        }

        // X-Frame-Options
        if (($value = config('security-headers.x_frame_options')) !== null) {
            $response->headers->set('X-Frame-Options', $value);
        }

        // X-XSS-Protection (legacy, but still useful for older browsers)
        if (($value = config('security-headers.x_xss_protection')) !== null) {
            $response->headers->set('X-XSS-Protection', $value);
        }

        // Referrer Policy
        if (($value = config('security-headers.referrer_policy')) !== null) {
            $response->headers->set('Referrer-Policy', $value);
        }

        // Permissions Policy
        if (($value = config('security-headers.permissions_policy')) !== null) {
            $response->headers->set('Permissions-Policy', $value);
        }

        return $response;
    }

    /**
     * Build the Content-Security-Policy header value.
     */
    private function buildCsp(string $nonce): string
    {
        $isDev = config('app.env') === 'local';

        // Vite dev server sources
        $viteOrigin = '';
        $viteWs = '';

        if ($isDev && config('security-headers.vite.enabled', true)) {
            $devServer = rtrim((string) config('security-headers.vite.dev_server', 'http://127.0.0.1:5173'), '/');

            // Derive the ws:// equivalent of the configured dev server URL
            $wsDev = preg_replace('/^https?/', 'ws', $devServer);

            // Also allow localhost variants so HMR works regardless of binding
            $localhostHttp = preg_replace('/127\.0\.0\.1/', 'localhost', $devServer);
            $localhostWs = preg_replace('/^https?/', 'ws', $localhostHttp ?? $devServer);

            $viteOrigin = " {$devServer} {$localhostHttp}";
            $viteWs = " {$wsDev} {$localhostWs}";
        }

        // Config-driven extra sources
        $extraScript = $this->sourcesToString(config('security-headers.csp.script_src', []));
        $extraStyle = $this->sourcesToString(config('security-headers.csp.style_src', []));
        $extraImg = $this->sourcesToString(config('security-headers.csp.img_src', []));
        $extraFont = $this->sourcesToString(config('security-headers.csp.font_src', []));
        $extraConnect = $this->sourcesToString(config('security-headers.csp.connect_src', []));

        $frameAncestors = $this->sourcesToString(config('security-headers.csp.frame_ancestors', ["'self'"]));
        $formAction = $this->sourcesToString(config('security-headers.csp.form_action', ["'self'"]));

        $directives = [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}' 'unsafe-eval'".$viteOrigin.$extraScript,
            "style-src 'self' 'unsafe-inline'".$viteOrigin.$extraStyle,
            "img-src 'self' data: blob:".$extraImg,
            "font-src 'self' data:".$extraFont,
            "connect-src 'self'".$viteOrigin.$viteWs.$extraConnect,
            'frame-ancestors'.' '.$frameAncestors,
            'form-action'.' '.$formAction,
            "base-uri 'self'",
            "object-src 'none'",
        ];

        return implode('; ', $directives);
    }

    /**
     * Convert an array of CSP source values into a space-prefixed string.
     *
     * @param  array<int, string>  $sources
     */
    private function sourcesToString(array $sources): string
    {
        if (empty($sources)) {
            return '';
        }

        return ' '.implode(' ', $sources);
    }
}
