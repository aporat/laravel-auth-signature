<?php

declare(strict_types=1);

namespace Aporat\AuthSignature;

use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * Service provider for the Laravel Auth Signature package.
 *
 * Registers the SignatureGenerator and ValidateAuthSignature middleware
 * in the service container and handles configuration merging and publishing.
 */
class AuthSignatureServiceProvider extends ServiceProvider implements DeferrableProvider
{
    /**
     * Path to the package's configuration file.
     */
    private const string CONFIG_PATH = __DIR__.'/../config/auth-signature.php';

    /**
     * Bootstrap application services and publish configuration.
     *
     * @param  Router  $router  The Laravel router instance.
     */
    public function boot(Router $router): void
    {
        // Only publish the configuration file when running in the console.
        if ($this->app->runningInConsole()) {
            $this->publishes([
                self::CONFIG_PATH => $this->app->configPath('auth-signature.php'),
            ], 'config');
        }

        // The router will resolve the middleware from the service container,
        // where we have already bound it with its dependencies.
        $router->aliasMiddleware('auth.signature', ValidateAuthSignature::class);
    }

    /**
     * Register services with the container.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(self::CONFIG_PATH, 'auth-signature');

        // Bind SignatureGenerator as a singleton. It will be instantiated only once.
        $this->app->singleton(SignatureGenerator::class, function (Application $app) {
            return new SignatureGenerator($app->make('config')->get('auth-signature'));
        });

        // Explicitly bind the middleware as a singleton. This ensures its dependencies
        // are resolved correctly and consistently from the container.
        $this->app->singleton(ValidateAuthSignature::class, function (Application $app) {
            return new ValidateAuthSignature(
                $app->make(SignatureGenerator::class),
                $app->make('config')->get('auth-signature')
            );
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * This is required for DeferrableProvider to work correctly. It tells Laravel
     * which services this provider is responsible for, allowing for lazy loading.
     *
     * @return array<int, class-string>
     */
    public function provides(): array
    {
        return [
            SignatureGenerator::class,
            ValidateAuthSignature::class,
        ];
    }
}
