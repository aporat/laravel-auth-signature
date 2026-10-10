<?php

declare(strict_types=1);

namespace Aporat\AuthSignature;

use Aporat\AuthSignature\Client\RequestSigner;
use Aporat\AuthSignature\Console\SignRequestCommand;
use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Psr\Http\Message\RequestInterface;

/**
 * Service provider for the Laravel Auth Signature package.
 *
 * Registers the SignatureGenerator and ValidateAuthSignature middleware
 * in the service container and handles configuration merging and publishing.
 */
class AuthSignatureServiceProvider extends ServiceProvider
{
    /**
     * Path to the package's configuration file.
     */
    private const string CONFIG_PATH = __DIR__.'/../config/auth-signature.php';

    /**
     * Bootstrap application services and publish configuration.
     *
     * This provider is intentionally *not* deferred. A deferred provider only
     * boots once one of the services it `provides()` is resolved, so the
     * middleware alias below — the very thing the router needs in order to
     * resolve that middleware — would never be registered.
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

            $this->commands([SignRequestCommand::class]);
        }

        $this->registerHttpClientMacro();

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

        // Bound as singletons so the config validation and the per-client checks
        // in the middleware constructor run once per process, not per request.
        $this->app->singleton(SignatureGenerator::class, fn (Application $app) => new SignatureGenerator(
            $app->make('config')->get('auth-signature', [])
        ));

        $this->app->singleton(RequestSigner::class, fn (Application $app) => new RequestSigner(
            $app->make(SignatureGenerator::class),
            $app->make('config')->get('auth-signature', [])
        ));

        $this->app->singleton(ValidateAuthSignature::class, fn (Application $app) => new ValidateAuthSignature(
            $app->make(SignatureGenerator::class),
            $app->make('config')->get('auth-signature', [])
        ));
    }

    /**
     * Registers `Http::withSignature($clientId, $authVersion = null, $secret = null)`.
     *
     * Signing happens in a Guzzle request middleware, so it covers the request
     * exactly as it is sent: final method, URL, query string and encoded body.
     * The client and auth version are checked when the macro is called.
     */
    private function registerHttpClientMacro(): void
    {
        PendingRequest::macro('withSignature', function (string $clientId, ?int $authVersion = null, ?string $secret = null): PendingRequest {
            /** @var PendingRequest $this */
            // Resolved from the current container on every call (not captured
            // at registration), as macros are static and outlive the app.
            $signer = Container::getInstance()->make(RequestSigner::class);
            $signer->assertCanSign($clientId, $authVersion);

            return $this->withRequestMiddleware(
                fn (RequestInterface $request): RequestInterface => $signer->sign($request, $clientId, $authVersion, $secret)
            );
        });
    }
}
