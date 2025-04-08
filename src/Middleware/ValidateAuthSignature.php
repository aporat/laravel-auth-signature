<?php

namespace Aporat\AuthSignature\Middleware;

use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\Laravel\Facades\FilterVar;
use Closure;
use Illuminate\Http\Request;

class ValidateAuthSignature
{
    protected SignatureGenerator $signatureGenerator;

    protected array $config;

    public function __construct(array $config)
    {
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

        if ($timestamp <= time() - (60 * 60 * 24 * 2) || $timestamp >= time() + 60 * 60 * 24 * 2) {
            throw new SignatureException('Please update your date & time on your device');
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
