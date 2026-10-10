# Laravel Auth Signature

A robust Laravel package providing a middleware for validating API requests with **HMAC-SHA256** signatures. It features configurable signature templates, version-specific authentication settings, and a secure, time-based validation to protect your endpoints.

[![Packagist Version](https://img.shields.io/packagist/v/aporat/laravel-auth-signature?style=flat-square)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![Packagist Downloads](https://img.shields.io/packagist/dt/aporat/laravel-auth-signature?style=flat-square)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![PHP Version](https://img.shields.io/badge/PHP-^8.4-777BB4.svg?style=flat-square)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-12|13-FF2D20.svg?style=flat-square)](https://laravel.com)
[![GitHub Actions CI](https://img.shields.io/github/actions/workflow/status/aporat/laravel-auth-signature/ci.yml?branch=main&style=flat-square)](https://github.com/aporat/laravel-auth-signature/actions)
[![Code Coverage](https://img.shields.io/codecov/c/github/aporat/laravel-auth-signature?style=flat-square)](https://codecov.io/github/aporat/laravel-auth-signature)
[![GitHub License](https://img.shields.io/github/license/aporat/laravel-auth-signature?style=flat-square)](LICENSE)

---

## ✨ Features

- **HMAC-SHA256 Validation**: Securely validates incoming API requests.
- **Configurable Signature Templates**: Easily define the exact order and components of the string-to-be-signed.
- **Version-Specific Rules**: Apply different secrets, states, and signature templates based on an `X-Auth-Version` header.
- **Timestamp Validation**: Rejects requests whose timestamp is outside a configurable window (±300 seconds by default). This limits how long a captured request can be replayed, but does not prevent replays inside the window: there is no nonce tracking.
- **Simple Middleware Integration**: Secure your routes with a single middleware alias: `auth.signature`.
- **Client-side Signing**: Sign outgoing requests with `Http::withSignature()`. Print the headers or a curl command with `php artisan auth-signature:sign`.
- **Clean and Modern Codebase**: Fully typed, tested, and built on modern PHP and Laravel features.

---

## 📋 Requirements

- **PHP**: ^8.4
- **Laravel**: 12.x or 13.x

---

## 🚀 Installation

1.  Install the package via Composer:
    ```bash
    composer require aporat/laravel-auth-signature
    ```

2.  Publish the configuration file. The service provider is auto-discovered.
    ```bash
    php artisan vendor:publish --provider="Aporat\AuthSignature\AuthSignatureServiceProvider" --tag="config"
    ```
    This will create a new configuration file at `config/auth-signature.php`.

---

## 🔧 Configuration

Edit `config/auth-signature.php` to define your clients, authentication versions, and settings.

```php
<?php

return [
    /*
    | Defines the time window, in seconds, either side of the server's clock
    | in which a request timestamp is accepted. Default is 300 seconds. This
    | narrows, but does not close, the window for replaying a captured request.
    */
    'timestamp_tolerance_seconds' => 300,

    /*
    | Define each client that can make signed requests.
    | The key is the Client ID sent in the `X-Auth-Client-ID` header.
    */
    'clients' => [
        'your-client-id' => [
            // The secret key used to sign requests for this client.
            'client_secret' => env('CLIENT_SECRET_KEY'),
            // The bundle ID or unique identifier for the client application.
            'bundle_id' => 'com.yourcompany.yourapp',
            // (Optional) The minimum auth version this client must use.
            'min_auth_level' => 10,
        ],
    ],

    /*
    | Define rules for different signature versions.
    | This allows you to evolve your signature algorithm over time.
    */
    'auth_versions' => [
        10 => [
            // (Optional) A version-specific secret appended to the client's secret.
            'secret' => env('AUTH_V10_SECRET'),
            // (Optional) A static string included in the signature for this version.
            'state' => 'some_static_string_for_v10',
            // (Optional) The exact order of components for the string-to-be-signed.
            'signature_template' => [
                'bundle_id', 'timestamp', 'client_id', 'state',
                'auth_version', 'method', 'signature', 'path',
            ],
        ],
    ],
];
```

Remember to add the corresponding keys to your `.env` file for security.

---

## 🛠️ Usage

### Applying the Middleware

Apply the `auth.signature` middleware to any route or route group that requires signature validation.

```php
// in routes/api.php
Route::middleware('auth.signature')->group(function () {
    Route::get('/orders', [OrderController::class, 'index']);
    Route::post('/orders', [OrderController::class, 'store']);
});
```

The middleware validates each incoming request and throws an `Aporat\AuthSignature\Exceptions\SignatureException` when validation fails. The exception's code holds the intended HTTP status (`400` malformed or missing header, `401` invalid signature or unknown client, `408` timestamp outside the window, `426` auth version too old or not configured), but the package does not yet turn it into that HTTP response: unless your application handles it, Laravel renders it as a `500` error and reports it to your logs. To return the intended status today, map it in `bootstrap/app.php`:

```php
use Aporat\AuthSignature\Exceptions\SignatureException;
use Illuminate\Foundation\Configuration\Exceptions;

->withExceptions(function (Exceptions $exceptions) {
    $exceptions->dontReport(SignatureException::class);
    $exceptions->render(fn (SignatureException $e) => response()->json(
        ['message' => $e->getMessage()],
        $e->getCode() >= 400 && $e->getCode() < 500 ? $e->getCode() : 401
    ));
})
```

### Replay protection

A valid request can be replayed, unchanged, for as long as its timestamp stays inside `timestamp_tolerance_seconds` of the server clock (in either direction). The package does not track nonces or previously seen signatures, so if you need one-time requests, add that check in your application.

### What the signature covers

The signature is an HMAC-SHA256 over the concatenation (no separator) of the
components named by the auth version's `signature_template`. The `signature`
component is the *canonical parameter string*, built from the request as
follows:

1. Parameter keys are lowercased.
2. Keys are sorted as **plain strings** (so `"10"` sorts before `"9"`).
3. Each key/value pair is encoded as `rawurlencode(key)=value`, and the pairs
   are joined with `&`.
4. Values encode as: `null` → empty, `true`/`false` → `1`/`0`, integers
   verbatim, floats keeping their zero fraction (`1.0`, not `1`), objects as
   compact JSON with recursively sorted keys, and everything else
   percent-encoded with `rawurlencode`.
5. List values expand to `key[0]`, `key[1]`, … **after** the sort, in list
   order — `tags[10]` therefore follows `tags[9]`, and `a[0]` precedes `a2`.
   Expansion is recursive, and an empty list encodes as `key=`.

The parameter set is read **off the wire**: the raw request body (JSON decoded
on a JSON request, `parse_str` on a form-urlencoded one) unioned with the raw
query string, with the body winning a key collision.

It is deliberately *not* `$request->input()`. Laravel's `TrimStrings` and
`ConvertEmptyStringsToNull` are global middleware, so they rewrite the parsed
bags before any route middleware — including this one — runs. Verifying against
those rewritten values means a client that legitimately signs `name=Rabi%20`
gets checked against `name=Rabi`, and every request carrying leading or
trailing whitespace in a string field is rejected with a mismatch the client
cannot see or fix. Reading the raw request leaves both transforms in place for
the application behind the middleware.

The **query string** is included because query parameters are readable through
`$request->input()` regardless of content type, so leaving them out would let
anyone append parameters to a captured request without invalidating it.
Uploaded files are *not* signed — their temporary paths differ on every
request — so a multipart upload signs only its text fields, which are read from
the parsed bag because PHP consumes a multipart body before `php://input` can
be read.

The `path` component is the percent-decoded path (`rawurldecode`, which leaves a
literal `+` alone), and `bundle_id` is taken from the client's configuration
verbatim.

### Generating a Signature

You can use the `SignatureGenerator` class to create a valid signature, which is useful for testing or for client-side implementations.

```php
use Aporat\AuthSignature\SignatureGenerator;

// Resolve the generator from the container
$generator = app(SignatureGenerator::class);

$signature = $generator->generate(
    clientId: 'your-client-id',
    authVersion: 10,
    timestamp: time(),
    method: 'GET',
    path: '/api/orders',
    params: ['page' => 1]
);

// The output will be a 64-character HMAC-SHA256 hash
// e.g., "b5f0029b48b61a9151528c11e74f115340f666d44a141b279d633036e88c0353"
```

### Example Client Request

A client would then make a request including the generated signature and other required headers.

```bash
# Store timestamp and generate signature first
TIMESTAMP=$(date +%s)
SIGNATURE="..." # Generate signature using the same timestamp

curl -X GET "http://yourapp.test/api/orders?page=1" \
  -H "X-Auth-Client-ID: your-client-id" \
  -H "X-Auth-Version: 10" \
  -H "X-Auth-Timestamp: $TIMESTAMP" \
  -H "X-Auth-Signature: $SIGNATURE"
```

### Signing outgoing requests (`Http::withSignature`)

The package registers a `withSignature()` macro on Laravel's HTTP client, so one Laravel app can call another that is protected by this middleware:

```php
use Illuminate\Support\Facades\Http;

// GET with a query string
Http::withSignature('ios-app')->get('https://api.example.com/api/orders', ['status' => 'open']);

// JSON body (the default)
Http::withSignature('ios-app')->post('https://api.example.com/api/orders', ['item' => 'book', 'qty' => 2]);

// Form body, explicit auth version, and a secret supplied at runtime
Http::withSignature('ios-app', authVersion: 20, secret: $secretFromVault)
    ->asForm()
    ->post('https://api.example.com/api/orders', ['item' => 'book']);
```

`withSignature(string $clientId, ?int $authVersion = null, ?string $secret = null)`:

- **`$clientId`**: a client from your `auth-signature.clients` config. The client's `bundle_id` is part of the signed string, so the client must be configured on the sending side too.
- **`$authVersion`**: defaults to the client's `min_auth_level` when that is a configured version, otherwise to the highest configured auth version.
- **`$secret`**: replaces the client's `client_secret` (useful when the sending app doesn't keep secrets in config). The auth version's `secret` is still appended, just as the middleware does.
- The timestamp is the current time when the request is sent.

An unknown client or auth version throws `InvalidConfigurationException` as soon as `withSignature()` is called.

The signature is computed in a request middleware just before the request leaves, so it covers the request exactly as sent: final method, path, query string and encoded body. It uses `SignatureGenerator` and reads the parameters the same way `ValidateAuthSignature` does:

- JSON bodies (`application/json`, `+json`) are decoded.
- Form bodies (`application/x-www-form-urlencoded`) are parsed.
- Query parameters are merged in, with body values winning on a key conflict.
- Other body types contribute no parameters, matching the middleware.
- Multipart bodies (`attach()`) can't be signed and throw `InvalidArgumentException`, because the middleware sees multipart fields only after PHP has parsed them.

The signed path is the URL path. If the receiving app is served from a subdirectory (so its `getPathInfo()` is shorter than the URL path), signatures won't match.

The macro works with `Http::fake()`: the request recorded by the fake carries the `X-Auth-*` headers.

### Signing from the command line (`auth-signature:sign`)

`php artisan auth-signature:sign` prints the headers for a request, signed with a configured client. It is useful for testing an endpoint with curl or for debugging a client's signature. The secrets are never printed.

```
php artisan auth-signature:sign {method} {url}
    [--client=]          client id (optional when exactly one client is configured)
    [--auth-version=]    defaults as for the macro
    [--data=]            JSON body, sent as application/json
    [--form=key=value]   form field, repeatable (sent form-urlencoded)
    [--query=key=value]  query parameter, repeatable
    [--timestamp=]       Unix timestamp to sign with (default: now)
    [--curl]             print a ready-to-run curl command
    [--debug] / -v       also print the canonical string being signed
```

`url` may be a full URL or a path, which is resolved against `app.url`. Form and query keys can use bracket syntax (`--form='tags[]=a'`).

```console
$ php artisan auth-signature:sign GET /api/orders --query=status=open --query=page=2
X-Auth-Client-ID: ios-app
X-Auth-Version: 20
X-Auth-Timestamp: 1760000000
X-Auth-Signature: 99ee00ab47d77973a5baff5150990bf8bb379a5445cf84ff337d976970e28aa7

$ php artisan auth-signature:sign POST /api/orders --data='{"item":"book","qty":2}' --curl
curl -X 'POST' 'https://api.example.com/api/orders' \
  -H 'X-Auth-Client-ID: ios-app' \
  -H 'X-Auth-Version: 20' \
  -H 'X-Auth-Timestamp: 1760000000' \
  -H 'X-Auth-Signature: 96edb3e6423e4d8b5b222a4ccbcac91d7f6fbe6cb1f71d4620dfb1ef7a97d694' \
  -H 'Content-Type: application/json' \
  --data-raw '{"item":"book","qty":2}'

$ php artisan auth-signature:sign POST /api/orders --form=item=book --form='tags[]=x' --debug
Method: POST
URL: https://api.example.com/api/orders
Path signed: /api/orders
String to sign: com.example.ios1760000000ios-appv20-state20POSTitem=book&tags%5B0%5D=x/api/orders

X-Auth-Client-ID: ios-app
...
```

The `--debug` canonical string has no secrets in it, but it does include the client's `bundle_id` and the auth version's `state`. Compare it with the string your client builds to find a mismatch.

The generated headers are valid only within `timestamp_tolerance_seconds` of the timestamp.

---

## 🧪 Testing

The package is fully tested. To run the test suite:

```bash
# Run all tests
composer test

# Run tests with code coverage
composer test-ci
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to fork the repository, create a feature branch, and open a pull request.

## 📜 License

This package is open-source software licensed under the **[MIT License](https://opensource.org/licenses/MIT)**.

## 💬 Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/aporat/laravel-auth-signature/issues).