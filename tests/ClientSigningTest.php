<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\AuthSignatureServiceProvider;
use Aporat\AuthSignature\Client\RequestSigner;
use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\SignatureGenerator;
use Aporat\FilterVar\FilterVarServiceProvider;
use GuzzleHttp\Psr7\Request as Psr7Request;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use InvalidArgumentException;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;

/**
 * Round trips: requests signed by `Http::withSignature()` and by the
 * `auth-signature:sign` command are replayed through the package's own
 * middleware on real routes.
 */
class ClientSigningTest extends TestCase
{
    /**
     * @var list<array{method: string, input: array<array-key, mixed>}>
     */
    private static array $reached = [];

    protected function setUp(): void
    {
        parent::setUp();
        self::$reached = [];
    }

    protected function getPackageProviders($app): array
    {
        return [FilterVarServiceProvider::class, AuthSignatureServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', 'http://localhost');
        $app['config']->set('auth-signature', [
            'timestamp_tolerance_seconds' => 300,
            'clients' => [
                'ios-app' => [
                    'client_secret' => 'ios-secret',
                    'bundle_id' => 'com.example.ios',
                    'min_auth_level' => 20,
                ],
            ],
            'auth_versions' => [
                10 => [],
                20 => ['secret' => 'v20-secret', 'state' => 'v20-state'],
            ],
        ]);
    }

    protected function defineRoutes($router): void
    {
        $controller = function (Request $request) {
            self::$reached[] = ['method' => $request->method(), 'input' => $request->all()];

            return response()->json(['ok' => true]);
        };

        Route::middleware('api')->prefix('api')->group(function () use ($controller) {
            Route::middleware('auth.signature')->group(function () use ($controller) {
                Route::get('/orders', $controller);
                Route::post('/orders', $controller);
                Route::put('/orders/{id}', $controller);
            });
        });
    }

    /**
     * Sends a request through Http::fake and returns the PSR-7 request exactly
     * as the client sent it.
     */
    private function captureSent(callable $send): RequestInterface
    {
        Http::fake(['*' => Http::response(['ok' => true])]);

        $send();

        $recorded = Http::recorded();
        $this->assertCount(1, $recorded);

        /** @var ClientRequest $request */
        $request = $recorded[0][0];

        return $request->toPsrRequest();
    }

    /**
     * Replays a captured client request against the application, so the real
     * middleware verifies it.
     */
    private function replay(RequestInterface $request): TestResponse
    {
        $server = ['HTTP_ACCEPT' => 'application/json'];

        foreach ($request->getHeaders() as $name => $values) {
            $key = strtoupper(str_replace('-', '_', $name));
            $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_'.$key] = implode(', ', $values);
        }

        $uri = $request->getUri();
        $target = $uri->getPath().($uri->getQuery() !== '' ? '?'.$uri->getQuery() : '');

        return $this->call($request->getMethod(), $target, [], [], [], $server, (string) $request->getBody());
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function replayWithHeaders(RequestInterface $request, array $headers): TestResponse
    {
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $this->replay($request);
    }

    /**
     * @return array<string, string>
     */
    private function parseHeaderLines(string $output): array
    {
        $headers = [];

        foreach (preg_split('/\R/', trim($output)) ?: [] as $line) {
            if (preg_match('/^(X-Auth-[A-Za-z-]+): (.*)$/', $line, $m)) {
                $headers[$m[1]] = $m[2];
            }
        }

        return $headers;
    }

    // --- Http::withSignature() ---------------------------------------------

    #[Test]
    public function macro_signs_a_get_request_with_its_query_string(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app')
            ->get('http://localhost/api/orders', ['status' => 'open', 'tags' => ['a', 'b'], 'q' => 'a b&c']));

        $this->assertSame('ios-app', $sent->getHeaderLine('X-Auth-Client-ID'));
        $this->assertSame('20', $sent->getHeaderLine('X-Auth-Version'));
        $this->assertEqualsWithDelta(time(), (int) $sent->getHeaderLine('X-Auth-Timestamp'), 5);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $sent->getHeaderLine('X-Auth-Signature'));

        $this->replay($sent)->assertOk();
        $this->assertSame('open', self::$reached[0]['input']['status']);
    }

    #[Test]
    public function macro_signs_a_json_post_body_as_sent(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app')
            ->withQueryParameters(['page' => 2])
            ->post('http://localhost/api/orders', [
                'item' => 'Café ☕',
                'qty' => 3,
                'price' => 9.5,
                'gift' => true,
                'note' => null,
                'meta' => ['b' => 1, 'a' => ['z' => 1, 'y' => 2]],
            ]));

        $this->assertStringContainsString('application/json', $sent->getHeaderLine('Content-Type'));

        $this->replay($sent)->assertOk();
        $this->assertSame('Café ☕', self::$reached[0]['input']['item']);
    }

    #[Test]
    public function macro_signs_a_form_post_body_as_sent(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app')
            ->asForm()
            ->post('http://localhost/api/orders', ['item' => 'book & pen', 'tags' => ['x', 'y']]));

        $this->assertStringContainsString('application/x-www-form-urlencoded', $sent->getHeaderLine('Content-Type'));

        $this->replay($sent)->assertOk();
        $this->assertCount(1, self::$reached);
    }

    #[Test]
    public function macro_signs_the_final_method_and_path(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app')
            ->baseUrl('http://localhost/api')
            ->put('orders/42', ['status' => 'shipped']));

        $this->assertSame('PUT', $sent->getMethod());
        $this->replay($sent)->assertOk();
    }

    #[Test]
    public function tampering_with_a_signed_request_is_rejected(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app')
            ->post('http://localhost/api/orders', ['qty' => 1]));

        $tampered = $sent->withBody(Utils::streamFor('{"qty":100}'));

        // A rejected signature currently surfaces as a 500 (see the review).
        $this->assertNotSame(200, $this->replay($tampered)->getStatusCode());
        $this->assertSame([], self::$reached);
    }

    #[Test]
    public function macro_accepts_an_explicit_auth_version(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app', 10)
            ->get('http://localhost/api/orders'));

        $this->assertSame('10', $sent->getHeaderLine('X-Auth-Version'));

        // Version 10 is below the client's min_auth_level of 20, so the
        // middleware refuses it even though the signature itself is valid.
        $this->assertNotSame(200, $this->replay($sent)->getStatusCode());

        $expected = $this->app->make(SignatureGenerator::class)->generate(
            'ios-app', 10, (int) $sent->getHeaderLine('X-Auth-Timestamp'), 'GET', '/api/orders', []
        );
        $this->assertSame($expected, $sent->getHeaderLine('X-Auth-Signature'));
    }

    #[Test]
    public function macro_secret_override_replaces_the_client_secret(): void
    {
        $sent = $this->captureSent(fn () => Http::withSignature('ios-app', null, 'not-the-secret')
            ->get('http://localhost/api/orders'));

        $this->assertNotSame(200, $this->replay($sent)->getStatusCode());
        $this->assertSame([], self::$reached);

        $sent = $this->captureSent(fn () => Http::withSignature('ios-app', null, 'ios-secret')
            ->get('http://localhost/api/orders'));

        $this->replay($sent)->assertOk();
    }

    #[Test]
    public function macro_rejects_an_unknown_client_when_called(): void
    {
        Http::fake();

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('unknown-app');

        Http::withSignature('unknown-app');
    }

    #[Test]
    public function macro_rejects_an_unknown_auth_version_when_called(): void
    {
        Http::fake();

        $this->expectException(InvalidConfigurationException::class);

        Http::withSignature('ios-app', 99);
    }

    #[Test]
    public function multipart_bodies_cannot_be_signed(): void
    {
        Http::fake();

        $this->expectException(InvalidArgumentException::class);

        Http::withSignature('ios-app')
            ->attach('file', 'contents', 'a.txt')
            ->post('http://localhost/api/orders', ['a' => 1]);
    }

    #[Test]
    public function signer_defaults_to_the_highest_version_without_min_auth_level(): void
    {
        $this->app['config']->set('auth-signature.clients.ios-app.min_auth_level', null);
        $this->app->forgetInstance(RequestSigner::class);

        $signer = $this->app->make(RequestSigner::class);

        $this->assertSame(20, $signer->defaultAuthVersion('ios-app'));
    }

    #[Test]
    public function signer_headers_match_the_generator(): void
    {
        $signer = $this->app->make(RequestSigner::class);
        $request = new Psr7Request('POST', 'http://localhost/api/orders?b=2', ['Content-Type' => 'application/json'], '{"a":1}');

        $headers = $signer->headers($request, 'ios-app', 20, null, 1_700_000_000);

        $this->assertSame([
            'X-Auth-Client-ID' => 'ios-app',
            'X-Auth-Version' => '20',
            'X-Auth-Timestamp' => '1700000000',
            'X-Auth-Signature' => $this->app->make(SignatureGenerator::class)
                ->generate('ios-app', 20, 1_700_000_000, 'POST', '/api/orders', ['a' => 1, 'b' => '2']),
        ], $headers);
    }

    // --- auth-signature:sign -----------------------------------------------

    #[Test]
    public function command_headers_verify_for_a_get_with_query(): void
    {
        $exit = Artisan::call('auth-signature:sign', [
            'method' => 'get',
            'url' => '/api/orders',
            '--query' => ['status=open', 'q=a b'],
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit, $output);
        $headers = $this->parseHeaderLines($output);
        $this->assertSame(['X-Auth-Client-ID', 'X-Auth-Version', 'X-Auth-Timestamp', 'X-Auth-Signature'], array_keys($headers));

        $this->replayWithHeaders(new Psr7Request('GET', 'http://localhost/api/orders?status=open&q=a%20b'), $headers)->assertOk();
    }

    #[Test]
    public function command_headers_verify_for_a_json_post(): void
    {
        $body = '{"item":"Café","qty":2,"meta":{"b":1,"a":2}}';

        $exit = Artisan::call('auth-signature:sign', [
            'method' => 'POST',
            'url' => 'http://localhost/api/orders',
            '--client' => 'ios-app',
            '--auth-version' => '20',
            '--data' => $body,
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit, $output);

        $request = new Psr7Request('POST', 'http://localhost/api/orders', ['Content-Type' => 'application/json'], $body);
        $this->replayWithHeaders($request, $this->parseHeaderLines($output))->assertOk();
    }

    #[Test]
    public function command_headers_verify_for_a_form_post(): void
    {
        $exit = Artisan::call('auth-signature:sign', [
            'method' => 'POST',
            'url' => '/api/orders',
            '--form' => ['item=book & pen', 'tags[]=x', 'tags[]=y'],
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit, $output);

        $request = new Psr7Request(
            'POST',
            'http://localhost/api/orders',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'item=book%20%26%20pen&tags%5B%5D=x&tags%5B%5D=y'
        );
        $this->replayWithHeaders($request, $this->parseHeaderLines($output))->assertOk();
        $this->assertCount(1, self::$reached);
    }

    #[Test]
    public function command_timestamp_override_is_deterministic(): void
    {
        Artisan::call('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders', '--timestamp' => '1700000000']);
        $headers = $this->parseHeaderLines(Artisan::output());

        $this->assertSame('1700000000', $headers['X-Auth-Timestamp']);
        $this->assertSame(
            $this->app->make(SignatureGenerator::class)->generate('ios-app', 20, 1_700_000_000, 'GET', '/api/orders', []),
            $headers['X-Auth-Signature']
        );
    }

    #[Test]
    public function command_prints_a_curl_command(): void
    {
        $exit = Artisan::call('auth-signature:sign', [
            'method' => 'POST',
            'url' => '/api/orders',
            '--query' => ['page=2'],
            '--data' => '{"note":"it\'s here"}',
            '--curl' => true,
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit, $output);
        $this->assertStringStartsWith("curl -X 'POST' 'http://localhost/api/orders?page=2'", $output);
        foreach (['X-Auth-Client-ID: ios-app', 'X-Auth-Version: 20', 'X-Auth-Timestamp: ', 'X-Auth-Signature: ', 'Content-Type: application/json'] as $header) {
            $this->assertStringContainsString("-H '".$header, $output);
        }
        $this->assertStringContainsString("--data-raw '{\"note\":\"it'\\''s here\"}'", $output);

        // The curl command is valid shell: run it through `sh` with `printf`
        // standing in for curl and check the arguments it receives.
        $script = str_replace(['curl ', "\\\n"], ['printf "%s\n" ', ''], trim($output));
        $args = explode("\n", trim((string) shell_exec($script)));
        $this->assertSame(['-X', 'POST', 'http://localhost/api/orders?page=2'], array_slice($args, 0, 3));
        $this->assertSame('{"note":"it\'s here"}', end($args));

        $headers = [];
        foreach ($args as $i => $arg) {
            if ($arg === '-H' && preg_match('/^(X-Auth-[A-Za-z-]+): (.*)$/', $args[$i + 1], $m)) {
                $headers[$m[1]] = $m[2];
            }
        }
        $request = new Psr7Request('POST', 'http://localhost/api/orders?page=2', ['Content-Type' => 'application/json'], '{"note":"it\'s here"}');
        $this->replayWithHeaders($request, $headers)->assertOk();
    }

    #[Test]
    public function command_debug_prints_the_canonical_string_but_never_the_secret(): void
    {
        foreach ([['--debug' => true], ['-v' => true]] as $flag) {
            Artisan::call('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders', '--query' => ['b=2', 'a=1'], '--timestamp' => '1700000000'] + $flag);
            $output = Artisan::output();

            $expected = $this->app->make(SignatureGenerator::class)
                ->stringToSign('ios-app', 20, 1_700_000_000, 'GET', '/api/orders', ['b' => '2', 'a' => '1']);

            $this->assertStringContainsString('String to sign: '.$expected, $output);
            $this->assertStringNotContainsString('ios-secret', $output);
            $this->assertStringNotContainsString('v20-secret', $output);
        }

        Artisan::call('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders']);
        $this->assertStringNotContainsString('String to sign', Artisan::output());
    }

    #[Test]
    public function command_fails_for_an_unknown_client(): void
    {
        $this->artisan('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders', '--client' => 'nope'])
            ->expectsOutputToContain('nope')
            ->assertFailed();
    }

    #[Test]
    public function command_fails_for_an_unknown_auth_version(): void
    {
        $this->artisan('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders', '--auth-version' => '99'])
            ->expectsOutputToContain('99')
            ->assertFailed();
    }

    #[Test]
    public function command_requires_a_client_when_several_are_configured(): void
    {
        $this->app['config']->set('auth-signature.clients.android-app', ['client_secret' => 'a', 'bundle_id' => 'b']);
        $this->app->forgetInstance(RequestSigner::class);

        $this->artisan('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders'])
            ->expectsOutputToContain('ios-app, android-app')
            ->assertFailed();
    }

    #[Test]
    public function command_rejects_bad_input(): void
    {
        $this->artisan('auth-signature:sign', ['method' => 'POST', 'url' => '/api/orders', '--data' => '{nope'])
            ->expectsOutputToContain('valid JSON')->assertFailed();

        $this->artisan('auth-signature:sign', ['method' => 'POST', 'url' => '/api/orders', '--data' => '{}', '--form' => ['a=1']])
            ->expectsOutputToContain('not both')->assertFailed();

        $this->artisan('auth-signature:sign', ['method' => 'GET', 'url' => '/api/orders', '--timestamp' => 'soon'])
            ->expectsOutputToContain('positive integer')->assertFailed();
    }
}
