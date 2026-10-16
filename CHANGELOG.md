# Changelog

All notable changes to this package are documented here.

## [Unreleased]

### Fixed

- A JSON object whose keys count up from zero (`{"0":[3],"1":[0]}`, a dictionary keyed by index) is now signed as an object. `ValidateAuthSignature` and `RequestSigner` decoded the body to associative arrays, which PHP cannot tell apart from a list, so the generator expanded such an object into `key[0][0]=…` pairs while the mobile clients sign it as sorted compact JSON, and every such request was rejected with `signature-mismatch`. Objects below the top level are now decoded as `stdClass` and `SignatureGenerator` canonicalises them as objects whatever their keys.

### Added

- `Http::withSignature($clientId, $authVersion = null, $secret = null)`, a macro on the HTTP client that signs outgoing requests at send time. It covers the final method, path, query string and JSON or form body, and reuses `SignatureGenerator` so the signature verifies against `ValidateAuthSignature`.
- `php artisan auth-signature:sign`: prints the `X-Auth-*` headers for a request. It also has `--curl` (ready-to-run curl command) and `--debug`/`-v` (canonical string being signed) options. Secrets are never printed.
- `Aporat\AuthSignature\Client\RequestSigner`, which signs a PSR-7 request. The macro and the command both use it.
- `SignatureGenerator::generate()` accepts an optional `$secret` that replaces the client's `client_secret`.
- `SignatureGenerator::stringToSign()` returns the canonical string for debugging.
