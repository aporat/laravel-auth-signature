<?php

namespace Aporat\AuthSignature;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;

use function rawurlencode;

readonly class SignatureGenerator
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        public array $config
    ) {}

    /**
     * @param  array<string, mixed>  $params
     */
    public function generate(string $clientId, int $authVersion, int $timestamp, string $method, string $path, array $params): string
    {
        $clientConfig = $this->getClientConfig($clientId);
        $versionConfig = $this->getAuthVersionConfig($authVersion);

        $canonicalParameters = $this->buildCanonicalParameters($params);
        $decodedPath = urldecode($path);

        $stringToSign = $this->buildStringToSign(
            $canonicalParameters,
            $decodedPath,
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
     */
    private function getClientConfig(string $clientId): array
    {
        $clientConfig = $this->config['clients'][$clientId] ?? null;

        if ($clientConfig === null) {
            throw InvalidConfigurationException::clientNotFound($clientId);
        }

        return $clientConfig;
    }

    /**
     * @return array<string, mixed>
     */
    private function getAuthVersionConfig(int $authVersion): array
    {
        $versionConfig = $this->config['auth_versions'][$authVersion] ?? null;

        if ($versionConfig === null) {
            throw InvalidConfigurationException::authVersionNotFound($authVersion);
        }

        return $versionConfig;
    }

    /**
     * @param  array<string, mixed>  $params
     */
    private function buildCanonicalParameters(array $params): string
    {
        ksort($params);

        $signatureParts = [];
        foreach ($params as $key => $value) {
            $encodedKey = rawurlencode(strtolower($key));

            $encodedValue = is_array($value)
                ? rawurlencode(json_encode($value, JSON_UNESCAPED_UNICODE))
                : rawurlencode((string) $value);

            $signatureParts[] = "{$encodedKey}={$encodedValue}";
        }

        return implode('&', $signatureParts);
    }

    /**
     * @param  array<string, mixed>  $clientConfig
     * @param  array<string, mixed>  $versionConfig
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
            'bundle_id' => urldecode($clientConfig['bundle_id']),
            'timestamp' => (string) $timestamp,
            'client_id' => $clientId,
            'state' => $versionConfig['state'] ?? '',
            'auth_version' => (string) $authVersion,
            'method' => $method,
            'signature' => $canonicalParameters,
            'path' => $path,
        ];

        $templateOrder = $versionConfig['signature_template'] ?? [
            'bundle_id', 'timestamp', 'client_id', 'state', 'auth_version', 'method', 'signature', 'path',
        ];

        $templateParts = [];
        foreach ($templateOrder as $key) {
            if (! array_key_exists($key, $components)) {
                throw InvalidConfigurationException::invalidTemplateKey($key, $authVersion);
            }
            $templateParts[] = $components[$key];
        }

        return implode('', $templateParts);
    }
}
