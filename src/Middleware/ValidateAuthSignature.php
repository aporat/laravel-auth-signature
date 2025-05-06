<?php

namespace Aporat\AuthSignature\Middleware;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\Facades\FilterVar;
use Closure;
use Illuminate\Http\Request;

class ValidateAuthSignature
{
    protected SignatureGenerator $signatureGenerator;

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(array $config)
    {

        if (empty($config['clients']) || ! is_array($config['clients'])) {
            throw new InvalidConfigurationException('Configuration must include a "clients" array.');
        }
        if (empty($config['auth_versions']) || ! is_array($config['auth_versions'])) {
            throw new InvalidConfigurationException('Configuration must include an "auth_versions" array.');
        }

        // Validate each client
        foreach ($config['clients'] as $clientId => $settings) {
            if (! isset($settings['client_secret']) || ! is_string($settings['client_secret'])) {
                throw new InvalidConfigurationException("Client '$clientId' must have a 'client_secret' string.");
            }
            if (! isset($settings['bundle_id']) || ! is_string($settings['bundle_id'])) {
                throw new InvalidConfigurationException("Client '$clientId' must have a 'bundle_id' string.");
            }
        }

        $this->config = $config;
        $this->signatureGenerator = new SignatureGenerator($config);
    }

    /**
     * @throws SignatureException
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $authVersion = FilterVar::filterValue('cast:int', $request->header('X-Auth-Version'));
        $timestamp = FilterVar::filterValue('cast:int', $request->header('X-Auth-Timestamp'));
        $clientId = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Client-ID'));
        $authSignature = FilterVar::filterValue('cast:string|normal_string|trim', $request->header('X-Auth-Signature'));

        if ($authVersion === null || $authVersion === false) {
            throw new SignatureException('Invalid or missing X-Auth-Version header.');
        }
        if ($timestamp === null || $timestamp === false) {
            throw new SignatureException('Invalid or missing X-Auth-Timestamp header.');
        }
        if (empty($clientId)) {
            throw new SignatureException('Invalid or missing X-Auth-Client-ID header.');
        }
        if (empty($authSignature)) {
            throw new SignatureException('Invalid or missing X-Auth-Signature header.');
        }

        if ($timestamp <= time() - (60 * 60 * 24 * 2) || $timestamp >= time() + 60 * 60 * 24 * 2) {
            throw new SignatureException('Please update your date & time on your device');
        }

        if (! isset($this->config['clients'][$clientId])) {
            throw new InvalidConfigurationException("No settings found for client '$clientId'.");
        }

        if (strlen($authSignature) != 64) {
            throw new SignatureException('You are currently running an older version of the app. Please update your application to continue.');
        }

        $method = $request->method();
        $path = $request->getPathInfo();
        $params = $request->all();

        $clientSettings = $this->config['clients'][$clientId];

        $checksum = $this->signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);

        // ignore empty POST requests
        if ($checksum != $authSignature && $request->getMethod() == 'POST' && empty($request->getContent())) {
            return response()->json();
        }

        if ($checksum != $authSignature && $request->getMethod() == 'POST' && $request->getContent() == '{}') {
            return response()->json();
        }

        if ($authVersion < $clientSettings['min_auth_level']) {
            throw new SignatureException('You are currently running an older version of the app. Please update your application to continue.');
        }

        if ($checksum != $authSignature) {
            throw new SignatureException('You are currently running an older version of the app. Please update your application to continue.');
        }

        return $next($request);
    }
}
