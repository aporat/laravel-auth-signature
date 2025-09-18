<?php

namespace Aporat\AuthSignature\Exceptions;

use Exception;

/**
 * Thrown during signature validation for issues like missing headers,
 * invalid timestamps, or a mismatched signature.
 *
 * This exception is designed to carry a relevant HTTP status code.
 */
class SignatureException extends Exception
{
    /**
     * Creates an exception for a missing or invalid header.
     */
    public static function missingHeader(string $headerName): self
    {
        // 400 Bad Request: The server cannot process the request due to a client error.
        return new self("Invalid or missing {$headerName} header.", 400);
    }

    /**
     * Creates an exception for an expired or out-of-date timestamp.
     */
    public static function timestampExpired(): self
    {
        // 408 Request Timeout: The server did not receive a complete request in time.
        return new self('Request timestamp is out of date.', 408);
    }

    /**
     * Creates an exception for when the client's auth version is too low.
     */
    public static function upgradeRequired(): self
    {
        // 426 Upgrade Required: The client should switch to a different protocol.
        return new self('A newer application version is required to proceed.', 426);
    }

    /**
     * Creates an exception for a signature that does not match the expected value.
     */
    public static function signatureMismatch(): self
    {
        // 401 Unauthorized: The client is not authenticated.
        return new self('Invalid signature.', 401);
    }
}
