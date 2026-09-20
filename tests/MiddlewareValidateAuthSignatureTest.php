<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\Exceptions\SignatureException;
use Aporat\AuthSignature\Middleware\ValidateAuthSignature;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\FilterVarServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;
use Illuminate\Foundation\Http\Middleware\TrimStrings;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\UploadedFile;
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
        // An unknown client id is attacker-controlled input, so it has to come
        // back as a SignatureException (401) rather than a configuration error
        // that the application would surface as a 500.
        $request = $this->createSignedRequest(['X-Auth-Client-ID' => 'unknown-client']);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        try {
            $middleware->handle($request, fn ($req) => new Response);
            $this->fail('Expected SignatureException was not thrown.');
        } catch (SignatureException $e) {
            $this->assertSame('Invalid signature.', $e->getMessage());
            $this->assertSame(401, $e->getCode());
        }
    }

    #[Test]
    public function it_rejects_request_with_unconfigured_auth_version(): void
    {
        // An auth version that is not configured is attacker-controlled input
        // too, so it must not reach the generator and blow up as a 500.
        $config = $this->config;
        $config['clients']['test-client']['min_auth_level'] = 0;

        $request = $this->createSignedRequest(['X-Auth-Version' => 999]);
        $middleware = new ValidateAuthSignature(new SignatureGenerator($config), $config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('A newer application version is required to proceed.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_rejects_request_with_missing_headers(): void
    {
        $request = Request::create('/api/test', 'POST', ['foo' => 'bar']);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid or missing X-Auth-Version header.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_rejects_signature_that_is_not_hex(): void
    {
        $request = $this->createSignedRequest(['X-Auth-Signature' => str_repeat('z', 64)]);
        $middleware = new ValidateAuthSignature($this->generator, $this->config);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid or missing X-Auth-Signature header.');

        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_rejects_a_json_request_with_unsigned_query_parameters(): void
    {
        // The signature covers the JSON body *and* the query string. Appending an
        // unsigned parameter to a captured request must not still validate, since
        // the application can read it back through $request->input().
        $params = ['foo' => 'bar'];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $request = Request::create(
            '/api/test?injected=1',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($params)
        );
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid signature.');

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_allows_a_signed_json_request(): void
    {
        $params = ['foo' => 'bar', 'nested' => ['b' => 2, 'a' => 1]];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $request = Request::create(
            '/api/test',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($params)
        );
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_allows_a_json_body_that_was_trimmed_after_the_client_signed_it(): void
    {
        // `TrimStrings` and `ConvertEmptyStringsToNull` are *global* middleware,
        // so they rewrite the parsed body before any route middleware sees it.
        // Checking the signature against those rewritten values rejects every
        // request whose payload carries surrounding whitespace, which the client
        // has no way to detect — the signature covers the bytes on the wire.
        $params = ['name' => 'Rabi ', 'bio' => ''];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $request = Request::create(
            '/api/test',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($params)
        );
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        (new TrimStrings)->handle($request, fn ($req) => new Response);
        (new ConvertEmptyStringsToNull)->handle($request, fn ($req) => new Response);

        // The transforms stay in effect for the application behind us.
        $this->assertSame('Rabi', $request->input('name'));
        $this->assertNull($request->input('bio'));

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_allows_query_parameters_that_were_trimmed_after_the_client_signed_them(): void
    {
        // The same transforms clean the query bag, so a GET carrying a trailing
        // space in a search term has to be read off the wire as well.
        $params = ['query' => 'india '];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'GET', '/api/test', $params);

        $request = Request::create('/api/test?query=india%20', 'GET');
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        (new TrimStrings)->handle($request, fn ($req) => new Response);

        $this->assertSame('india', $request->input('query'));

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_rejects_a_request_whose_parsed_body_was_rewritten_to_match_the_signature(): void
    {
        // Reading the raw body must not become a way to sign one payload and
        // have the application act on another: the bytes on the wire are what
        // gets checked, whatever the parsed bag was later made to say.
        $params = ['foo' => 'bar'];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $request = Request::create(
            '/api/test',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode(['foo' => 'tampered'])
        );
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        $request->json()->replace($params);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid signature.');

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $middleware->handle($request, fn ($req) => new Response);
    }

    #[Test]
    public function it_allows_a_signed_form_urlencoded_request(): void
    {
        $params = ['name' => 'Rabi ', 'tags' => ['India', 'travel']];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $request = Request::create(
            '/api/test',
            'POST',
            server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            content: http_build_query($params)
        );
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_allows_a_multipart_request_whose_file_is_not_signed(): void
    {
        // Clients sign the text fields of a multipart upload but not the file
        // itself — its temporary path is different on every request, so folding
        // it into the signed set (as $request->all() would) could never match.
        $params = ['foo' => 'bar'];
        $timestamp = time();
        $signature = $this->generator->generate('test-client', 10, $timestamp, 'POST', '/api/test', $params);

        $file = UploadedFile::fake()->create('avatar.jpg', 1);
        $request = Request::create('/api/test', 'POST', $params, files: ['file' => $file]);
        $request->headers->add([
            'X-Auth-Version' => 10,
            'X-Auth-Timestamp' => $timestamp,
            'X-Auth-Client-ID' => 'test-client',
            'X-Auth-Signature' => $signature,
        ]);

        $middleware = new ValidateAuthSignature($this->generator, $this->config);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function it_rejects_a_non_integer_timestamp_tolerance(): void
    {
        $config = $this->config;
        $config['timestamp_tolerance_seconds'] = 'soon';

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Configuration value "timestamp_tolerance_seconds" must be a non-negative integer.');

        new ValidateAuthSignature($this->generator, $config);
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
