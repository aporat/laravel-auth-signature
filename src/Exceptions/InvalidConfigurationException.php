<?php

declare(strict_types=1);

namespace Aporat\AuthSignature\Exceptions;

use RuntimeException;

/**
 * Thrown when the auth-signature package configuration is invalid or missing required keys.
 */
class InvalidConfigurationException extends RuntimeException
{
    /**
     * Creates an exception for a missing 'clients' array in the config.
     */
    public static function missingClientsArray(): self
    {
        return new self('Configuration must include a "clients" array.');
    }

    /**
     * Creates an exception for a missing 'auth_versions' array in the config.
     */
    public static function missingAuthVersionsArray(): self
    {
        return new self('Configuration must include an "auth_versions" array.');
    }

    /**
     * Creates an exception for a client missing its 'client_secret'.
     */
    public static function missingClientSecret(string $clientId): self
    {
        return new self("Client '{$clientId}' must have a 'client_secret' string.");
    }

    /**
     * Creates an exception for a client missing its 'bundle_id'.
     */
    public static function missingBundleId(string $clientId): self
    {
        return new self("Client '{$clientId}' must have a 'bundle_id' string.");
    }

    /**
     * Creates an exception for when a client's configuration cannot be found.
     */
    public static function clientNotFound(string $clientId): self
    {
        return new self("Configuration for client ID '{$clientId}' not found.");
    }

    /**
     * Creates an exception for when an auth version's configuration cannot be found.
     */
    public static function authVersionNotFound(int $authVersion): self
    {
        return new self("Configuration for auth version '{$authVersion}' not found.");
    }

    /**
     * Creates an exception for a timestamp tolerance that is not a
     * non-negative integer number of seconds.
     */
    public static function invalidTimestampTolerance(): self
    {
        return new self('Configuration value "timestamp_tolerance_seconds" must be a non-negative integer.');
    }

    /**
     * Creates an exception for a signature template that is missing or empty.
     */
    public static function invalidTemplate(int $authVersion): self
    {
        return new self("Signature template for auth version '{$authVersion}' must be a non-empty array.");
    }

    /**
     * Creates an exception for an invalid key in a signature template.
     */
    public static function invalidTemplateKey(string $key, int $authVersion): self
    {
        return new self("Invalid signature template key '{$key}' for auth version '{$authVersion}'.");
    }
}
