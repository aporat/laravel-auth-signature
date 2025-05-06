<?php

declare(strict_types=1);

namespace Aporat\AuthSignature;

use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;

/**
 * Service provider for the Laravel CloudWatch Logger package.
 *
 * Registers the CloudWatch logger factory as a service and handles configuration
 * merging and publishing for CloudWatch logging integration.
 */
class AuthSignatureServiceProvider extends ServiceProvider implements DeferrableProvider
{
    /**
     * Path to the package's configuration file.
     *
     * @var string
     */
    private const string CONFIG_PATH = __DIR__.'/../config/auth-signature.php';

    /**
     * Bootstrap application services and publish configuration.
     */
    public function boot(): void
    {
        $this->publishes([self::CONFIG_PATH => config_path('auth-signature.php')], 'config');

        $this->app['router']->aliasMiddleware('auth.signature', ValidateAuthSignature::class);
    }

    /**
     * Register services with the container.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(self::CONFIG_PATH, 'auth-signature');

        $this->app->singleton(SignatureGenerator::class, function ($app) {
            return new SignatureGenerator(config('auth-signature'));
        });
    }
}
