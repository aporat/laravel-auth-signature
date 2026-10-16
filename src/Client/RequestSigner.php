<?php

declare(strict_types=1);

namespace Aporat\AuthSignature\Client;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\SignatureGenerator;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use stdClass;

use function array_filter;
use function array_keys;
use function ctype_digit;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function max;
use function parse_str;
use function str_contains;
use function strtolower;
use function time;

/**
 * Signs outgoing PSR-7 requests so that `ValidateAuthSignature` accepts them.
 *
 * The parameters are read from the request exactly the way the middleware
 * reads them on the receiving side: the JSON body (decoded) or the
 * form-urlencoded body (`parse_str`), unioned with the query string, the body
 * winning a key collision. The signature itself comes from
 * {@see SignatureGenerator}, so client and server share one canonicalisation.
 */
readonly class RequestSigner
{
    public const string HEADER_CLIENT_ID = 'X-Auth-Client-ID';

    public const string HEADER_VERSION = 'X-Auth-Version';

    public const string HEADER_TIMESTAMP = 'X-Auth-Timestamp';

    public const string HEADER_SIGNATURE = 'X-Auth-Signature';

    /**
     * @param  array<string, mixed>  $config  The `auth-signature` configuration.
     */
    public function __construct(
        private SignatureGenerator $generator,
        private array $config,
    ) {}

    /**
     * Returns the request with the four X-Auth-* headers set.
     *
     * @param  int|null  $authVersion  Defaults to {@see defaultAuthVersion()}.
     * @param  string|null  $secret  Replaces the client's configured secret.
     * @param  int|null  $timestamp  Defaults to the current time.
     *
     * @throws InvalidConfigurationException for an unknown client or auth version
     * @throws InvalidArgumentException for a body that cannot be signed
     */
    public function sign(
        RequestInterface $request,
        string $clientId,
        ?int $authVersion = null,
        ?string $secret = null,
        ?int $timestamp = null,
    ): RequestInterface {
        foreach ($this->headers($request, $clientId, $authVersion, $secret, $timestamp) as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    /**
     * The X-Auth-* headers for a request.
     *
     * @return array<string, string>
     *
     * @throws InvalidConfigurationException
     * @throws InvalidArgumentException
     */
    public function headers(
        RequestInterface $request,
        string $clientId,
        ?int $authVersion = null,
        ?string $secret = null,
        ?int $timestamp = null,
    ): array {
        $authVersion ??= $this->defaultAuthVersion($clientId);
        $timestamp ??= time();

        $signature = $this->generator->generate(
            $clientId,
            $authVersion,
            $timestamp,
            $request->getMethod(),
            $this->path($request),
            $this->parameters($request),
            $secret
        );

        return [
            self::HEADER_CLIENT_ID => $clientId,
            self::HEADER_VERSION => (string) $authVersion,
            self::HEADER_TIMESTAMP => (string) $timestamp,
            self::HEADER_SIGNATURE => $signature,
        ];
    }

    /**
     * The string that is signed for a request, for debugging. Contains no secrets.
     *
     * @throws InvalidConfigurationException
     * @throws InvalidArgumentException
     */
    public function stringToSign(RequestInterface $request, string $clientId, int $authVersion, int $timestamp): string
    {
        return $this->generator->stringToSign(
            $clientId,
            $authVersion,
            $timestamp,
            $request->getMethod(),
            $this->path($request),
            $this->parameters($request)
        );
    }

    /**
     * Checks that a client and auth version can be used for signing, without
     * signing anything.
     *
     * @throws InvalidConfigurationException
     */
    public function assertCanSign(string $clientId, ?int $authVersion = null): void
    {
        $this->clientConfig($clientId);
        $authVersion ??= $this->defaultAuthVersion($clientId);

        if (! is_array($this->authVersions()[$authVersion] ?? null)) {
            throw InvalidConfigurationException::authVersionNotFound($authVersion);
        }
    }

    /**
     * The auth version used when none is given: the client's
     * `min_auth_level` when it is a configured version, otherwise the highest
     * configured auth version.
     *
     * @throws InvalidConfigurationException
     */
    public function defaultAuthVersion(string $clientId): int
    {
        $minimum = $this->clientConfig($clientId)['min_auth_level'] ?? null;

        if (is_string($minimum) && ctype_digit($minimum)) {
            $minimum = (int) $minimum;
        }

        if (is_int($minimum) && isset($this->authVersions()[$minimum])) {
            return $minimum;
        }

        $versions = array_filter(array_keys($this->authVersions()), is_int(...));

        if ($versions === []) {
            throw InvalidConfigurationException::missingAuthVersionsArray();
        }

        return max($versions);
    }

    /**
     * The request path as the middleware sees it (`getPathInfo()`).
     */
    public function path(RequestInterface $request): string
    {
        $path = $request->getUri()->getPath();

        return $path === '' ? '/' : $path;
    }

    /**
     * The parameters covered by the signature, read the way the middleware
     * reads them: body (JSON or form-urlencoded) first, then the query string.
     *
     * @return array<array-key, mixed>
     *
     * @throws InvalidArgumentException for a multipart body
     */
    public function parameters(RequestInterface $request): array
    {
        return $this->bodyParameters($request) + $this->queryParameters($request);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function bodyParameters(RequestInterface $request): array
    {
        $contentType = strtolower($request->getHeaderLine('Content-Type'));

        if (str_contains($contentType, 'multipart/form-data')) {
            throw new InvalidArgumentException(
                'Multipart requests cannot be signed: the receiving middleware reads multipart fields '
                .'after Laravel has parsed and trimmed them. Send the fields as JSON or form-urlencoded.'
            );
        }

        $isJson = str_contains($contentType, '/json') || str_contains($contentType, '+json');
        $isForm = str_contains($contentType, 'application/x-www-form-urlencoded');

        if (! $isJson && ! $isForm) {
            // Other bodies are not part of the signature on the receiving side.
            return [];
        }

        $content = $this->readBody($request);

        if ($content === '') {
            return [];
        }

        if ($isJson) {
            // Objects stay `stdClass` below the top level, as in the middleware,
            // so `{"0":1,"1":2}` is signed as an object and not as a list.
            $decoded = json_decode($content);

            if ($decoded instanceof stdClass) {
                return (array) $decoded;
            }

            return is_array($decoded) ? $decoded : [];
        }

        parse_str($content, $parsed);

        return $parsed;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function queryParameters(RequestInterface $request): array
    {
        $query = $request->getUri()->getQuery();

        if ($query === '') {
            return [];
        }

        parse_str($query, $parsed);

        return $parsed;
    }

    private function readBody(RequestInterface $request): string
    {
        $body = $request->getBody();

        if (! $body->isSeekable()) {
            throw new InvalidArgumentException('Requests with a non-seekable body cannot be signed.');
        }

        $body->rewind();
        $content = $body->getContents();
        $body->rewind();

        return $content;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidConfigurationException
     */
    private function clientConfig(string $clientId): array
    {
        $clients = $this->config['clients'] ?? null;
        $client = is_array($clients) ? ($clients[$clientId] ?? null) : null;

        if (! is_array($client)) {
            throw InvalidConfigurationException::clientNotFound($clientId);
        }

        return $client;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function authVersions(): array
    {
        $versions = $this->config['auth_versions'] ?? null;

        return is_array($versions) ? $versions : [];
    }
}
