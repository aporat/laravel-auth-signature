<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\Laravel\FilterVarServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class MiddlewareValidateAuthSignatureTest extends TestCase
{
    protected $signatureGenerator;

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
                    'min_auth_level' => 1
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
                        'auth_version',
                        'state',
                        'method',
                        'signature',
                        'version_signature',
                        'path',
                    ],
                ],
            ],
        ];
    }

    #[Test]
    public function it_passes_with_valid_signature(): void
    {
        // Test data
        $timestamp = time();
        $clientId = 'client-id';
        $authVersion = 1;
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value'];

        // Create a request with valid headers
        $request = Request::create($path, $method, $params);
        $request->headers->set('X-Auth-Version', (string) $authVersion);
        $request->headers->set('X-App-Name', 'test-app');
        $request->headers->set('X-Auth-Timestamp', (string) $timestamp);
        $request->headers->set('X-Auth-Client-ID', $clientId);
        $request->headers->set('User-Agent', "App (iOS; $authVersion; $clientId)");

        // Generate the expected signature
        $signatureGenerator = new SignatureGenerator($this->config);
        $expectedSignature = $signatureGenerator->generate(
            $clientId,
            $authVersion,
            $timestamp,
            $method,
            $path,
            $params
        );
        $request->headers->set('X-Auth-Signature', $expectedSignature);

        // Instantiate middleware and test
        $middleware = new ValidateAuthSignature($this->config);
        $response = $middleware->handle($request, fn($req) => new Response('OK'));

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }
}