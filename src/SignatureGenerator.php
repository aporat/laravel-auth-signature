<?php

declare(strict_types=1);

namespace Aporat\AuthSignature;

use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const SORT_STRING;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;

use function array_is_list;
use function hash_hmac;
use function implode;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function json_encode;
use function ksort;
use function rawurldecode;
use function rawurlencode;
use function strtolower;
use function uksort;

/**
 * Builds the HMAC-SHA256 signature for a request.
 *
 * The canonical form mirrors the mobile clients (`APSignedAPIClient` on iOS,
 * `RequestSigning` on Android) byte for byte — any drift here rejects traffic
 * those clients sign correctly, so the ordering and encoding rules below are
 * deliberately explicit.
 */
readonly class SignatureGenerator
{
    /**
     * The default order of the string-to-sign components when an auth version
     * does not declare its own `signature_template`.
     *
     * @var list<string>
     */
    private const array DEFAULT_TEMPLATE = [
        'bundle_id', 'timestamp', 'client_id', 'state', 'auth_version', 'method', 'signature', 'path',
    ];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private array $config
    ) {}

    /**
     * @param  array<string, mixed>  $params
     *
     * @throws InvalidConfigurationException
     */
    public function generate(string $clientId, int $authVersion, int $timestamp, string $method, string $path, array $params): string
    {
        $clientConfig = $this->getClientConfig($clientId);
        $versionConfig = $this->getAuthVersionConfig($authVersion);

        $stringToSign = $this->buildStringToSign(
            $this->buildCanonicalParameters($params),
            // Clients sign the decoded path (`URL.path` on iOS). `getPathInfo()`
            // hands us the raw, percent-encoded path, and `rawurldecode` is the
            // right inverse: `urldecode` would also turn a literal `+` in the
            // path into a space, which no client does.
            rawurldecode($path),
            $method,
            $clientId,
            $clientConfig,
            $authVersion,
            $versionConfig,
            $timestamp
        );

        $clientSecret = $clientConfig['client_secret'].($versionConfig['secret'] ?? '');

        return hash_hmac('sha256', $stringToSign, $clientSecret);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidConfigurationException
     */
    private function getClientConfig(string $clientId): array
    {
        $clientConfig = $this->config['clients'][$clientId] ?? null;

        if (! is_array($clientConfig)) {
            throw InvalidConfigurationException::clientNotFound($clientId);
        }

        return $clientConfig;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidConfigurationException
     */
    private function getAuthVersionConfig(int $authVersion): array
    {
        $versionConfig = $this->config['auth_versions'][$authVersion] ?? null;

        if (! is_array($versionConfig)) {
            throw InvalidConfigurationException::authVersionNotFound($authVersion);
        }

        return $versionConfig;
    }

    /**
     * Builds the canonicalised `key=value` list that clients sign.
     *
     * Keys are lowercased and sorted as plain strings *before* list values are
     * expanded into `key[i]=…` pairs, which is the order the clients produce.
     * Sorting the expanded keys instead would reorder `a[0]` against `a2`, and
     * `tags[10]` against `tags[2]`.
     *
     * @param  array<array-key, mixed>  $params
     */
    private function buildCanonicalParameters(array $params): string
    {
        $lowercased = [];

        foreach ($params as $key => $value) {
            $lowercased[strtolower((string) $key)] = $value;
        }

        // Comparing with `strcmp` rather than `ksort()`: PHP casts numeric-string
        // array keys to integers, and the default comparison would then order
        // "9" before "10" where the clients sort "10" before "9".
        uksort($lowercased, static fn (int|string $a, int|string $b): int => strcmp((string) $a, (string) $b));

        $parts = [];

        foreach ($lowercased as $key => $value) {
            $parts[] = $this->encodePair((string) $key, $value);
        }

        return implode('&', $parts);
    }

    /**
     * Encodes a single parameter, expanding list values recursively.
     */
    private function encodePair(string $key, mixed $value): string
    {
        $encodedKey = rawurlencode($key);

        if (is_array($value) && array_is_list($value)) {
            if ($value === []) {
                return $encodedKey.'=';
            }

            $pairs = [];
            foreach ($value as $index => $element) {
                $pairs[] = $this->encodePair($key.'['.$index.']', $element);
            }

            return implode('&', $pairs);
        }

        if (is_array($value)) {
            return $encodedKey.'='.rawurlencode($this->encodeObject($value));
        }

        return $encodedKey.'='.$this->encodeValue($value);
    }

    /**
     * Compact JSON with recursively sorted object keys, matching
     * `JSONSerialization` with `.sortedKeys` and `.withoutEscapingSlashes`.
     *
     * @param  array<array-key, mixed>  $value
     */
    private function encodeObject(array $value): string
    {
        return json_encode(
            $this->sortKeysRecursively($value),
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR
        );
    }

    private function encodeValue(mixed $value): string
    {
        if ($value === null) {
            return '';
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if (is_int($value)) {
            return (string) $value;
        }

        if (is_float($value)) {
            // `(string) 1.0` is "1" in PHP, but Swift and Kotlin both render that
            // Double as "1.0". Encoding it as JSON keeps the zero fraction and the
            // shortest round-trip representation the clients use.
            return json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
        }

        return rawurlencode((string) $value);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function sortKeysRecursively(array $data): array
    {
        if (! array_is_list($data)) {
            ksort($data, SORT_STRING);
        }

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sortKeysRecursively($value);
            }
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $clientConfig
     * @param  array<string, mixed>  $versionConfig
     *
     * @throws InvalidConfigurationException
     */
    private function buildStringToSign(
        string $canonicalParameters,
        string $path,
        string $method,
        string $clientId,
        array $clientConfig,
        int $authVersion,
        array $versionConfig,
        int $timestamp
    ): string {
        $components = [
            'bundle_id' => (string) $clientConfig['bundle_id'],
            'timestamp' => (string) $timestamp,
            'client_id' => $clientId,
            'state' => (string) ($versionConfig['state'] ?? ''),
            'auth_version' => (string) $authVersion,
            'method' => $method,
            'signature' => $canonicalParameters,
            'path' => $path,
        ];

        $templateOrder = $versionConfig['signature_template'] ?? self::DEFAULT_TEMPLATE;

        if (! is_array($templateOrder) || $templateOrder === []) {
            throw InvalidConfigurationException::invalidTemplate($authVersion);
        }

        $templateParts = [];
        foreach ($templateOrder as $key) {
            if (! is_string($key) || ! array_key_exists($key, $components)) {
                throw InvalidConfigurationException::invalidTemplateKey((string) $key, $authVersion);
            }
            $templateParts[] = $components[$key];
        }

        return implode('', $templateParts);
    }
}
