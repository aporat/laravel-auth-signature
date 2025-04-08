# Laravel Auth Signature
A Laravel package providing a middleware for validating API requests with HMAC-SHA256 signatures, featuring configurable template orders and version-specific authentication settings.

[![Latest Stable Version](https://img.shields.io/packagist/v/aporat/laravel-auth-signature.svg?style=flat-square&logo=composer)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![Monthly Downloads](https://img.shields.io/packagist/dm/aporat/laravel-auth-signature.svg?style=flat-square&logo=composer)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![Codecov](https://img.shields.io/codecov/c/github/aporat/laravel-auth-signature?style=flat-square)](https://codecov.io/github/aporat/laravel-auth-signature)
[![Laravel Version](https://img.shields.io/badge/Laravel-12.x-orange.svg?style=flat-square)](https://laravel.com/docs/12.x)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/aporat/laravel-auth-signature/ci.yml?style=flat-square)
[![License](https://img.shields.io/packagist/l/aporat/laravel-auth-signature.svg?style=flat-square)](https://github.com/aporat/laravel-auth-signature/blob/master/LICENSE)

A Laravel package for signature-based authentication, providing a middleware to validate API requests using HMAC-SHA256 signatures.

## Requirements
- **PHP**: 8.4 or higher
- **Laravel**: 10.x, 11.x, 12.x

## Installation
Install the package via [Composer](https://getcomposer.org/):

```bash
composer require aporat/laravel-auth-signature
```

The service provider (`AuthSignatureServiceProvider`) is automatically registered via Laravel's package discovery. If auto-discovery is disabled, add it to `config/app.php`:

```php
'providers' => [
// ...
Aporat\\AuthSignature\\Laravel\\AuthSignatureServiceProvider::class,
],
```

Publish the configuration file:

```bash
php artisan vendor:publish --provider="Aporat\\AuthSignature\\Laravel\\AuthSignatureServiceProvider" --tag="config"
```

This copies `auth-signature.php` to your `config/` directory.

## Configuration

Edit `config/auth-signature.php` to define your clients and auth versions:

```php
<?php

return [
    'clients' => [
        'your-client-id' => [
            'client_secret' => env('AUTH_CLIENT_SECRET', 'your-secret'),
            'bundle_id' => env('AUTH_BUNDLE_ID', 'com.your.app'),
            'min_auth_level' => env('AUTH_MIN_LEVEL', 1),
        ],
    ],
    'auth_versions' => [
        1 => [
            'secret' => env('AUTH_VERSION_SECRET', 'optional-secret'),
            'state' => env('AUTH_STATE', 'RSA2048'),
            'signature_template' => [
                'bundle_id',
                'timestamp',
                'client_id',
                'state',
                'auth_version',
                'method',
                'signature',
                'path',
            ],
        ],
    ],
];
```

Update your `.env` file with your secrets:

```env
AUTH_CLIENT_SECRET=your-secret-key
AUTH_BUNDLE_ID=com.your.app
AUTH_MIN_LEVEL=1
AUTH_VERSION_SECRET=optional-version-secret
AUTH_STATE=RSA2048
```

- **`clients`**: Defines client-specific settings like `client_secret` and `bundle_id`. `min_auth_level` enforces a minimum auth version.
- **`auth_versions`**: Configures version-specific settings, including an optional `secret` appended to `client_secret`, a `state` value, and the `signature_template` order for HMAC-SHA256 generation.

## Usage

### Middleware
Apply the `ValidateAuthSignature` middleware to routes using its alias:

```php
// routes/api.php
Route::get('/test', function () {
    return response()->json(['message' => 'Validated!']);
})->middleware('auth.signature');
```

The middleware validates requests by checking headers like `X-Auth-Signature`, `X-Auth-Version`, `X-Auth-Timestamp`, and `X-Auth-Client-ID`.

### Manual Instantiation
Resolve an instance with the config in a controller or service:

```php
use Aporat\\AuthSignature\\Middleware\\ValidateAuthSignature;

$validateAuthSignature = new ValidateAuthSignature(config('auth-signature', []));
$response = $validateAuthSignature->handle($request, fn($req) => response('Validated!'));
```

Or use dependency injection (requires binding adjustment in the service provider):

```php
use Aporat\\AuthSignature\\Middleware\\ValidateAuthSignature;
use Illuminate\\Http\\Request;

class AuthController extends Controller
{
    public function validateRequest(Request $request, ValidateAuthSignature $middleware)
    {
        return $middleware->handle($request, fn($req) => response()->json(['message' => 'Validated!']));
    }
}
```

### Generating a Signature
For testing, generate a signature manually:

```php
use Aporat\\AuthSignature\\SignatureGenerator;

$signatureGenerator = new SignatureGenerator(config('auth-signature'));
$signature = $signatureGenerator->generate(
    'your-client-id',
    1, // auth_version
    time(), // timestamp
    'GET',
    '/test',
    ['key' => 'value']
);
echo $signature;
```

Send a request with headers:

```bash
curl -X GET \
  -H "X-Auth-Version: 1" \
  -H "X-App-Name: test-app" \
  -H "X-Auth-Timestamp: [timestamp]" \
  -H "X-Auth-Client-ID: your-client-id" \
  -H "X-Auth-Signature: [generated-signature]" \
  -H "User-Agent: App (iOS; 1; your-client-id)" \
  "http://your-app.test/test?key=value"
```

## Testing
Run the package's unit tests:

```bash
vendor/bin/phpunit
```

With coverage:

```bash
vendor/bin/phpunit --coverage-text --coverage-clover coverage.xml --log-junit junit.xml
```

Requires Xdebug or PCOV for coverage reports.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License
This package is open-sourced under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](LICENSE) file for details.

## Support
- **Issues**: [github.com/aporat/laravel-auth-signature/issues](https://github.com/aporat/laravel-auth-signature/issues)
- **Source**: [github.com/aporat/laravel-auth-signature](https://github.com/aporat/laravel-auth-signature)