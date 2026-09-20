<?php

declare(strict_types=1);

namespace Aporat\AuthSignature\Middleware;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\Facades\FilterVar;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use function abs;
use function ctype_xdigit;
use function hash_equals;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function parse_str;
use function str_contains;
use function strlen;
use function strtolower;
use function time;

/**
 * Rejects requests whose HMAC-SHA256 signature headers are missing, stale, or
 * do not match the signature computed from the request itself.
 */
class ValidateAuthSignature
{
    /**
     * Length of the hex-encoded SHA-256 signature carried by `X-Auth-Signature`.
     */
    private const int SIGNATURE_LENGTH = 64;

    /**
     * Fallback clock-skew window, in seconds, when the config does not set one.
     */
    private const int DEFAULT_TIMESTAMP_TOLERANCE = 300;

    /**
     * Clock-skew window, in seconds, either side of the server's current time.
     */
    private readonly int $timestampTolerance;

    /**
     * Per-client settings, keyed by client id.
     *
     * @var array<string, array<string, mixed>>
     */
    private readonly array $clients;

    /**
     * Per-auth-version settings, keyed by version number.
     *
     * @var array<int|string, array<string, mixed>>
     */
    private readonly array $authVersions;

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws InvalidConfigurationException
     */
    public function __construct(
        private readonly SignatureGenerator $signatureGenerator,
        array $config,
    ) {
        $this->validateConfig($config);

        $this->clients = $config['clients'];
        $this->authVersions = $config['auth_versions'];

        $tolerance = $config['timestamp_tolerance_seconds'] ?? self::DEFAULT_TIMESTAMP_TOLERANCE;

        if (! is_int($tolerance) || $tolerance < 0) {
            throw InvalidConfigurationException::invalidTimestampTolerance();
        }

        $this->timestampTolerance = $tolerance;
    }

    /**
     * Handle an incoming request.
     *
     * @throws SignatureException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $headers = $this->extractAuthHeaders($request);

        $this->validateTimestamp($headers['timestamp']);
        $this->validateClientRules($headers['clientId'], $headers['authVersion']);

        $expectedSignature = $this->signatureGenerator->generate(
            $headers['clientId'],
            $headers['authVersion'],
            $headers['timestamp'],
            $request->method(),
            $request->getPathInfo(),
            $this->signedParameters($request)
        );

        if (! hash_equals($expectedSignature, $headers['authSignature'])) {
            throw SignatureException::signatureMismatch();
        }

        return $next($request);
    }

    /**
     * The parameter set covered by the signature, read off the wire rather than
     * out of the parsed request.
     *
     * `$request->input()` looks like the natural source, but it returns the
     * bags *after* Laravel's global `TrimStrings` and
     * `ConvertEmptyStringsToNull` middleware have rewritten them, and global
     * middleware runs ahead of every route middleware including this one. A
     * client that signs `name=Rabi%20` is then checked against `name=Rabi`, so
     * any request with leading or trailing whitespace in a string field fails
     * with a mismatch the client cannot see, reproduce, or fix. Reading the raw
     * body and the raw query string compares against exactly what was signed
     * and leaves those transforms in place for the application behind us.
     *
     * The body and the query string are both covered. Query parameters stay
     * readable through `$request->input()` whatever the content type, so
     * leaving them out would let an attacker append arbitrary parameters to a
     * captured request without breaking its signature. Uploaded files are still
     * excluded — their temporary paths differ on every request and can
     * therefore never be signed.
     *
     * @return array<array-key, mixed>
     */
    private function signedParameters(Request $request): array
    {
        // Body first on a key collision, the way `input()` resolves one.
        return $this->rawBodyParameters($request) + $this->rawQueryParameters($request);
    }

    /**
     * The request body as the client sent it.
     *
     * @return array<array-key, mixed>
     */
    private function rawBodyParameters(Request $request): array
    {
        // Symfony caches the body on the first `getContent()` call — which
        // Laravel has already made to fill the JSON bag — so this is the
        // original payload, not a re-read of an exhausted stream. The transforms
        // rewrite the bag they parsed out of it, never the cached string.
        $content = $request->getContent();

        if ($request->isJson()) {
            $decoded = $content === '' ? null : json_decode($content, true);

            // A body something else has already consumed leaves nothing to
            // re-read. Falling back to the parsed bag keeps such a request
            // verifiable rather than failing every one of them outright.
            return is_array($decoded) ? $decoded : $request->json()->all();
        }

        if ($content !== '' && $this->isFormUrlEncoded($request)) {
            parse_str($content, $parsed);

            return $parsed;
        }

        // Multipart bodies are consumed by PHP before any of this runs, so
        // `php://input` is empty and the parsed bag is all there is.
        return $request->request->all();
    }

    /**
     * The query string as the client sent it.
     *
     * @return array<array-key, mixed>
     */
    private function rawQueryParameters(Request $request): array
    {
        $queryString = $request->server->get('QUERY_STRING');

        // Either there were no query parameters, or the request was built in
        // memory without one. The bag answers both cases.
        if (! is_string($queryString) || $queryString === '') {
            return $request->query->all();
        }

        parse_str($queryString, $parsed);

        return $parsed;
    }

    private function isFormUrlEncoded(Request $request): bool
    {
        $contentType = $request->headers->get('CONTENT_TYPE');

        return is_string($contentType)
            && str_contains(strtolower($contentType), 'application/x-www-form-urlencoded');
    }

    /**
     * Extracts and performs initial validation on authentication headers.
     *
     * @return array{authVersion: int, timestamp: int, clientId: string, authSignature: string}
     *
     * @throws SignatureException
     */
    private function extractAuthHeaders(Request $request): array
    {
        // `cast:int` turns an absent header into 0, so the raw header has to be
        // checked for presence separately — otherwise a request with no
        // timestamp at all reports as "expired" rather than as malformed.
        $authVersion = FilterVar::filterValue('cast:int', $this->requireHeader($request, 'X-Auth-Version'));
        if (! is_int($authVersion) || $authVersion <= 0) {
            throw SignatureException::missingHeader('X-Auth-Version');
        }

        $timestamp = FilterVar::filterValue('cast:int', $this->requireHeader($request, 'X-Auth-Timestamp'));
        if (! is_int($timestamp) || $timestamp <= 0) {
            throw SignatureException::missingHeader('X-Auth-Timestamp');
        }

        $clientId = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Client-ID'));
        if (! is_string($clientId) || $clientId === '') {
            throw SignatureException::missingHeader('X-Auth-Client-ID');
        }

        $authSignature = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Signature'));
        if (! is_string($authSignature) || strlen($authSignature) !== self::SIGNATURE_LENGTH || ! ctype_xdigit($authSignature)) {
            throw SignatureException::missingHeader('X-Auth-Signature');
        }

        return compact('authVersion', 'timestamp', 'clientId', 'authSignature');
    }

    /**
     * @throws SignatureException
     */
    private function requireHeader(Request $request, string $name): string
    {
        $value = $request->header($name);

        if (! is_string($value) || $value === '') {
            throw SignatureException::missingHeader($name);
        }

        return $value;
    }

    /**
     * Validates that the timestamp is within the allowed tolerance window.
     *
     * @throws SignatureException
     */
    private function validateTimestamp(int $timestamp): void
    {
        if (abs(time() - $timestamp) > $this->timestampTolerance) {
            throw SignatureException::timestampExpired();
        }
    }

    /**
     * Validates rules specific to the client, like minimum auth version.
     *
     * Both the client id and the auth version come straight off the wire, so
     * neither may surface as an uncaught `InvalidConfigurationException` (and a
     * 500) when it does not match the configuration — that would hand any
     * unauthenticated caller a way to fill the error log with server errors.
     *
     * @throws SignatureException
     */
    private function validateClientRules(string $clientId, int $authVersion): void
    {
        $clientSettings = $this->clients[$clientId] ?? null;

        if (! is_array($clientSettings)) {
            throw SignatureException::unknownClient();
        }

        $minAuthLevel = $clientSettings['min_auth_level'] ?? 0;
        if (is_int($minAuthLevel) && $authVersion < $minAuthLevel) {
            throw SignatureException::upgradeRequired();
        }

        if (! isset($this->authVersions[$authVersion])) {
            throw SignatureException::upgradeRequired();
        }
    }

    /**
     * Validates the structure of the configuration array upon instantiation.
     *
     * @param  array<string, mixed>  $config
     *
     * @throws InvalidConfigurationException
     */
    private function validateConfig(array $config): void
    {
        if (empty($config['clients']) || ! is_array($config['clients'])) {
            throw InvalidConfigurationException::missingClientsArray();
        }

        if (empty($config['auth_versions']) || ! is_array($config['auth_versions'])) {
            throw InvalidConfigurationException::missingAuthVersionsArray();
        }

        foreach ($config['clients'] as $clientId => $settings) {
            if (! is_array($settings) || empty($settings['client_secret']) || ! is_string($settings['client_secret'])) {
                throw InvalidConfigurationException::missingClientSecret((string) $clientId);
            }
            if (empty($settings['bundle_id']) || ! is_string($settings['bundle_id'])) {
                throw InvalidConfigurationException::missingBundleId((string) $clientId);
            }
        }
    }
}
