<?php

declare(strict_types=1);

namespace PhilipRehberger\SecurityHeaders;

use Illuminate\Support\ServiceProvider;

class SecurityHeadersServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/security-headers.php',
            'security-headers'
        );
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/security-headers.php' => config_path('security-headers.php'),
            ], 'security-headers-config');
        }
    }
}
