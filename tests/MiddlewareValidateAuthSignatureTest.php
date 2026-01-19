<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\FilterVarServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class MiddlewareValidateAuthSignatureTest extends TestCase
{
    private array $config;

    private SignatureGenerator $generator;

    protected function getPackageProviders($app): array
    {
        return [FilterVarServiceProvider::class];
    }

    /**
     * Get the default application bootstrap file.
     *
     * @param  Application  $app
     */
    protected function getDefaultApplicationBootstrapFile($app): ?string
    {
        return null;
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = [
            'timestamp_tolerance_seconds' => 60,
            'clients' => [
                'test-client' => [
                    'client_secret' => 'test-secret',
                    'bundle_id' => 'com.example.app',
                    'min_auth_level' => 10,
                ],
            ],
            'auth_versions' => [
                10 => ['secret' => 'v10-secret', 'state' => 'v10-state'],
            ],
        ];

        $this->generator = new SignatureGenerator($this->config);
    }

    #[Test]
    public function it_allows_a_valid_request_to_pass(): void
    {
        $request = $this->createSignedRequest();
        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_rejects_request_with_unknown_client_id(): void
    {
        $request = $this->createSignedRequest(['X-Auth-Client-ID' => 'unknown-client']);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $expectedMessage = "Configuration for client ID 'unknown-client' not found.";

        try {
            $middleware->handle($request, fn ($req) => new Response);
            $this->fail('Expected InvalidConfigurationException was not thrown.');
        } catch (InvalidConfigurationException $e) {
            $this->assertSame($expectedMessage, $e->getMessage());
        }
    }

    #[Test]
    public function it_rejects_request_with_old_timestamp(): void
    {
        $request = $this->createSignedRequest(['X-Auth-Timestamp' => time() - 100]);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Request timestamp is out of date.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_rejects_request_with_version_below_minimum(): void
    {
        $request = $this->createSignedRequest(['X-Auth-Version' => 9]);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('A newer application version is required to proceed.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_rejects_request_with_signature_mismatch(): void
    {
        $request = $this->createSignedRequest(['X-Auth-Signature' => str_repeat('a', 64)]);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid signature.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    private function createSignedRequest(array $headerOverrides = []): Request
    {
        $method = 'POST';
        $path = '/api/test';
        $params = ['foo' => 'bar'];
        $timestamp = time();

        $headers = [
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
        ];

        $signature = $this->generator->generate(
            $headers['X-Auth-Client-ID'],
            $headers['X-Auth-Version'],
            $headers['X-Auth-Timestamp'],
            $method,
            $path,
            $params
        );
        $headers['X-Auth-Signature'] = $signature;

        foreach ($headerOverrides as $key => $value) {
            $headers[$key] = $value;
        }

        $request = Request::create($path, $method, $params);
        $request->headers->add($headers);

        return $request;
    }
}
