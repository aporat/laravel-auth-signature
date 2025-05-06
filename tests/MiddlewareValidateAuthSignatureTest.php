<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Aporat\FilterVar\FilterVarServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class MiddlewareValidateAuthSignatureTest extends TestCase
{
    protected array $config;

    protected function getPackageProviders($app): array
    {
        return [
            FilterVarServiceProvider::class,
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = [
            'clients' => [
                'client-id' => [
                    'client_secret' => 'secret',
                    'bundle_id' => 'com.test.app',
                    'min_auth_level' => 2,
                ],
            ],
            'auth_versions' => [
                1 => [
                    'secret' => 'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ',
                    'state' => 'RSA2048',
                    'signature_template' => [
                        'bundle_id',
                        'timestamp',
                        'client_id',
                        'state',
                        'auth_version',
                        'method',
                        'signature',
                        'path',
                    ],
                ],
            ],
        ];
    }

    #[Test]
    public function it_passes_with_valid_signature(): void
    {
        $timestamp = time();
        $clientId = 'client-id';
        $authVersion = 2; // Above min_auth_level
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);
        $request->headers->set('User-Agent', "App (iOS; $authVersion; $clientId)");

        $signatureGenerator = new \Aporat\AuthSignature\SignatureGenerator($this->config);
        $expectedSignature = $signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);
        $request->headers->set('X-Auth-Signature', $expectedSignature);

        $middleware = new ValidateAuthSignature($this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK'));

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    #[Test]
    public function it_throws_exception_for_missing_client(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("No settings found for client 'unknown-client'");

        $timestamp = time();
        $clientId = 'unknown-client';
        $authVersion = 1;
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);
        $request->headers->set('X-Auth-Signature', 'dummy-signature');

        $middleware = new ValidateAuthSignature($this->config);
        $middleware->handle($request, fn ($req) => new Response('OK'));
    }

    #[Test]
    public function it_throws_exception_for_invalid_timestamp(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Please update your date & time on your device');

        $timestamp = time() - (60 * 60 * 24 * 3); // 3 days ago
        $clientId = 'client-id';
        $authVersion = 2;
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);
        $request->headers->set('X-Auth-Signature', 'dummy-signature');

        $middleware = new ValidateAuthSignature($this->config);
        $middleware->handle($request, fn ($req) => new Response('OK'));
    }

    #[Test]
    public function it_throws_exception_for_invalid_signature_length(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('You are currently running an older version of the app. Please update your application to continue.');

        $timestamp = time();
        $clientId = 'client-id';
        $authVersion = 2;
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);
        $request->headers->set('X-Auth-Signature', 'short-signature'); // Less than 64 chars

        $middleware = new ValidateAuthSignature($this->config);
        $middleware->handle($request, fn ($req) => new Response('OK'));
    }

    #[Test]
    public function it_throws_exception_for_below_min_auth_level(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('You are currently running an older version of the app. Please update your application to continue.');

        $timestamp = time();
        $clientId = 'client-id';
        $authVersion = 1; // Below min_auth_level of 2
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);

        $signatureGenerator = new \Aporat\AuthSignature\SignatureGenerator($this->config);
        $expectedSignature = $signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);
        $request->headers->set('X-Auth-Signature', $expectedSignature);

        $middleware = new ValidateAuthSignature($this->config);
        $middleware->handle($request, fn ($req) => new Response('OK'));
    }
}
