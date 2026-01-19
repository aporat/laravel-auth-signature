<?php

namespace Aporat\AuthSignature\Middleware;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\Facades\FilterVar;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidateAuthSignature
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        public SignatureGenerator $signatureGenerator,
        public array $config,
        public int $timestampTolerance = 300
    ) {
        $this->validateConfig($config);
        $this->timestampTolerance = $config['timestamp_tolerance_seconds'] ?? $this->timestampTolerance;
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
            $request->all()
        );

        if (! hash_equals($expectedSignature, $headers['authSignature'])) {
            throw SignatureException::signatureMismatch();
        }

        return $next($request);
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
        $authVersion = FilterVar::filterValue('cast:int', $request->header('X-Auth-Version'));
        if ($authVersion === null || $authVersion === false) {
            throw SignatureException::missingHeader('X-Auth-Version');
        }

        $timestamp = FilterVar::filterValue('cast:int', $request->header('X-Auth-Timestamp'));
        if ($timestamp === null || $timestamp === false) {
            throw SignatureException::missingHeader('X-Auth-Timestamp');
        }

        $clientId = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Client-ID'));
        if (empty($clientId)) {
            throw SignatureException::missingHeader('X-Auth-Client-ID');
        }

        $authSignature = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Signature'));
        if (empty($authSignature) || strlen($authSignature) !== 64) {
            throw SignatureException::missingHeader('X-Auth-Signature');
        }

        return compact('authVersion', 'timestamp', 'clientId', 'authSignature');
    }

    /**
     * Validates that the timestamp is within the allowed tolerance window.
     *
     * @throws SignatureException
     */
    private function validateTimestamp(int $timestamp): void
    {
        $currentTime = time();
        if ($timestamp < ($currentTime - $this->timestampTolerance) || $timestamp > ($currentTime + $this->timestampTolerance)) {
            throw SignatureException::timestampExpired();
        }
    }

    /**
     * Validates rules specific to the client, like minimum auth version.
     *
     * @throws SignatureException
     */
    private function validateClientRules(string $clientId, int $authVersion): void
    {
        $clientSettings = $this->config['clients'][$clientId] ?? null;

        if ($clientSettings === null) {
            throw InvalidConfigurationException::clientNotFound($clientId);
        }

        $minAuthLevel = $clientSettings['min_auth_level'] ?? 0;
        if ($authVersion < $minAuthLevel) {
            throw SignatureException::upgradeRequired();
        }
    }

    /**
     * Validates the structure of the configuration array upon instantiation.
     *
     * @param  array<string, mixed>  $config
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
            if (empty($settings['client_secret']) || ! is_string($settings['client_secret'])) {
                throw InvalidConfigurationException::missingClientSecret($clientId);
            }
            if (empty($settings['bundle_id']) || ! is_string($settings['bundle_id'])) {
                throw InvalidConfigurationException::missingBundleId($clientId);
            }
        }
    }
}
