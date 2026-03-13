<?php

declare(strict_types=1);

namespace PhilipRehberger\SecurityHeaders\Tests;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Orchestra\Testbench\TestCase;
use PhilipRehberger\SecurityHeaders\SecurityHeaders;
use PhilipRehberger\SecurityHeaders\SecurityHeadersServiceProvider;

class SecurityHeadersTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SecurityHeadersServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.env', 'testing');
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private function handle(Request $request, array $config = []): Response
    {
        foreach ($config as $key => $value) {
            config([$key => $value]);
        }

        $middleware = new SecurityHeaders;

        /** @var Response $response */
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        return $response;
    }

    private function makeRequest(): Request
    {
        return Request::create('/');
    }

    // ---------------------------------------------------------------------------
    // Standard headers
    // ---------------------------------------------------------------------------

    public function test_sets_x_content_type_options(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    public function test_sets_x_frame_options(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertSame('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
    }

    public function test_sets_x_xss_protection(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertSame('1; mode=block', $response->headers->get('X-XSS-Protection'));
    }

    public function test_sets_referrer_policy(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertSame('strict-origin-when-cross-origin', $response->headers->get('Referrer-Policy'));
    }

    public function test_sets_permissions_policy(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertSame(
            'geolocation=(), camera=(), microphone=(), payment=()',
            $response->headers->get('Permissions-Policy')
        );
    }

    // ---------------------------------------------------------------------------
    // CSP
    // ---------------------------------------------------------------------------

    public function test_sets_csp_header(): void
    {
        $response = $this->handle($this->makeRequest());

        $this->assertNotNull($response->headers->get('Content-Security-Policy'));
    }

    public function test_csp_contains_nonce(): void
    {
        $response = $this->handle($this->makeRequest());

        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("'nonce-", $csp);
    }

    public function test_nonce_shared_to_views(): void
    {
        $request = $this->makeRequest();
        $this->handle($request);

        $shared = app('view')->getShared();

        $this->assertArrayHasKey('cspNonce', $shared);
        $this->assertNotEmpty($shared['cspNonce']);
    }

    public function test_nonce_set_on_request_attributes(): void
    {
        $request = $this->makeRequest();
        $this->handle($request);

        $this->assertNotNull($request->attributes->get('csp_nonce'));
    }

    // ---------------------------------------------------------------------------
    // HSTS
    // ---------------------------------------------------------------------------

    public function test_hsts_not_set_when_disabled(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.hsts.enabled' => false,
        ]);

        $this->assertNull($response->headers->get('Strict-Transport-Security'));
    }

    public function test_hsts_set_when_enabled(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.hsts.enabled' => true,
            'security-headers.hsts.max_age' => 31536000,
            'security-headers.hsts.include_subdomains' => true,
        ]);

        $this->assertSame(
            'max-age=31536000; includeSubDomains',
            $response->headers->get('Strict-Transport-Security')
        );
    }

    // ---------------------------------------------------------------------------
    // Custom CSP sources
    // ---------------------------------------------------------------------------

    public function test_custom_csp_sources_included(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.script_src' => ['https://cdn.example.com'],
            'security-headers.csp.img_src' => ['https://images.example.com'],
            'security-headers.csp.connect_src' => ['wss://ws.example.com'],
        ]);

        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('https://cdn.example.com', $csp);
        $this->assertStringContainsString('https://images.example.com', $csp);
        $this->assertStringContainsString('wss://ws.example.com', $csp);
    }

    // ---------------------------------------------------------------------------
    // CSP disabled
    // ---------------------------------------------------------------------------

    public function test_csp_disabled_skips_header(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.enabled' => false,
        ]);

        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    // ---------------------------------------------------------------------------
    // Null disables individual headers
    // ---------------------------------------------------------------------------

    public function test_each_header_can_be_disabled_with_null(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.x_content_type_options' => null,
            'security-headers.x_frame_options' => null,
            'security-headers.x_xss_protection' => null,
            'security-headers.referrer_policy' => null,
            'security-headers.permissions_policy' => null,
        ]);

        $this->assertNull($response->headers->get('X-Content-Type-Options'));
        $this->assertNull($response->headers->get('X-Frame-Options'));
        $this->assertNull($response->headers->get('X-XSS-Protection'));
        $this->assertNull($response->headers->get('Referrer-Policy'));
        $this->assertNull($response->headers->get('Permissions-Policy'));
    }

    // ---------------------------------------------------------------------------
    // unsafe-eval / unsafe-inline toggles
    // ---------------------------------------------------------------------------

    public function test_csp_includes_unsafe_eval_by_default(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("'unsafe-eval'", $csp);
    }

    public function test_csp_excludes_unsafe_eval_when_disabled(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.unsafe_eval' => false,
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringNotContainsString("'unsafe-eval'", $csp);
    }

    public function test_csp_includes_unsafe_inline_by_default(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("'unsafe-inline'", $csp);
    }

    public function test_csp_excludes_unsafe_inline_when_disabled(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.unsafe_inline' => false,
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringNotContainsString("'unsafe-inline'", $csp);
    }

    // ---------------------------------------------------------------------------
    // Vite dev server in local environment
    // ---------------------------------------------------------------------------

    public function test_vite_dev_server_added_in_local_env(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'app.env' => 'local',
            'security-headers.vite.enabled' => true,
            'security-headers.vite.dev_server' => 'http://127.0.0.1:5173',
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('http://127.0.0.1:5173', $csp);
    }

    public function test_vite_ws_origins_added_in_local_env(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'app.env' => 'local',
            'security-headers.vite.enabled' => true,
            'security-headers.vite.dev_server' => 'http://127.0.0.1:5173',
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('ws://127.0.0.1:5173', $csp);
    }

    public function test_vite_not_added_in_production_env(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'app.env' => 'production',
            'security-headers.vite.enabled' => true,
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringNotContainsString('127.0.0.1:5173', $csp);
    }

    // ---------------------------------------------------------------------------
    // CSP directive details
    // ---------------------------------------------------------------------------

    public function test_csp_contains_frame_ancestors(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("frame-ancestors 'self'", $csp);
    }

    public function test_csp_custom_frame_ancestors(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.frame_ancestors' => ["'self'", 'https://portal.example.com'],
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('https://portal.example.com', $csp);
    }

    public function test_csp_contains_form_action(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("form-action 'self'", $csp);
    }

    public function test_csp_custom_style_src(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.style_src' => ['https://fonts.bunny.net'],
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('https://fonts.bunny.net', $csp);
    }

    public function test_csp_custom_font_src(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.csp.font_src' => ['https://fonts.gstatic.com'],
        ]);
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString('https://fonts.gstatic.com', $csp);
    }

    public function test_hsts_without_include_subdomains(): void
    {
        $response = $this->handle($this->makeRequest(), [
            'security-headers.hsts.enabled' => true,
            'security-headers.hsts.max_age' => 31536000,
            'security-headers.hsts.include_subdomains' => false,
        ]);

        $hsts = $response->headers->get('Strict-Transport-Security');

        $this->assertSame('max-age=31536000', $hsts);
        $this->assertStringNotContainsString('includeSubDomains', $hsts);
    }

    public function test_csp_contains_base_uri(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("base-uri 'self'", $csp);
    }

    public function test_csp_contains_object_src_none(): void
    {
        $response = $this->handle($this->makeRequest());
        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("object-src 'none'", $csp);
    }
}
