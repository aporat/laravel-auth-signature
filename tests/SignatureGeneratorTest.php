<?php

declare(strict_types=1);

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use Aporat\AuthSignature\SignatureGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class SignatureGeneratorTest extends TestCase
{
    /**
     * Provides different scenarios for successful signature generation.
     */
    public static function signatureGenerationDataProvider(): array
    {
        $baseConfig = [
            'clients' => [
                'test-client' => [
                    'client_secret' => 'test-secret',
                    'bundle_id' => 'com.example.app',
                ],
            ],
            'auth_versions' => [
                1 => ['secret' => 'v1-secret', 'state' => 'v1-state'],
                2 => [
                    'secret' => 'v2-secret',
                    'state' => 'v2-state',
                    'signature_template' => ['method', 'path', 'timestamp', 'signature'],
                ],
            ],
        ];

        return [
            'default template with simple params' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'GET',
                'path' => '/api/users',
                'params' => ['page' => 2, 'filter' => 'active'],
                'expectedSignature' => '8e765128c8e080d5091be50598af9614ec4d6d1ca6f9960fff4681044113ed64',
            ],
            'custom template with empty params' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 2,
                'timestamp' => 1726669826,
                'method' => 'POST',
                'path' => '/api/users',
                'params' => [],
                'expectedSignature' => 'c448dc17d80cdc85c5e99cee1f04cddf15c58d7e487da266f3a658842fa95692',
            ],
            'default template with associative array param' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'PUT',
                'path' => '/api/users/1',
                'params' => ['user' => ['name' => 'John Doe', 'role' => 'admin']],
                'expectedSignature' => '113e083bbe4a6afb3fadcc7665b92e823103851393bfa1b87d743d6541d9a4ee',
            ],
            'default template with sequential array param uses bracket notation' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'GET',
                'path' => '/api/tags',
                'params' => ['tags' => ['swift', 'ios']],
                'expectedSignature' => '1dc3da9374aa9ca12abdfc657d4c2386fcbd44d56359b9db7d1bff60f0aba9e4',
            ],
            'default template with empty array param' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'GET',
                'path' => '/api/tags',
                'params' => ['tags' => []],
                'expectedSignature' => '6bc48ede274ac1a72fcdb5921efb21f3ea3a7014daf9e8c61a86dd05db024cdb',
            ],
            'default template with array containing int and bool elements' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'POST',
                'path' => '/api/items',
                'params' => ['flags' => [true, false, 42]],
                'expectedSignature' => 'a247930890d2e1c501c3fe73984adf15ca65394a989550a1836865cddba6f38c',
            ],
            'default template with array keys sorted alongside scalar keys' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'POST',
                'path' => '/api/profile',
                'params' => ['tags' => ['swift', 'ios'], 'name' => 'test'],
                'expectedSignature' => '25e96eb1d52bded81590e72955cfd98d4fcedf766b36745c9d1d3eab75602c0c',
            ],
            'default template with special characters' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'GET',
                'path' => '/api/path with spaces',
                'params' => ['email' => 'test+user@example.com'],
                'expectedSignature' => '02350719245ee2b2027ab4abfbb25ee91e3df0317793f6b30b2b274d464b9d69',
            ],
        ];
    }

    #[Test]
    #[DataProvider('signatureGenerationDataProvider')]
    public function it_generates_correct_signatures(
        array $config,
        string $clientId,
        int $authVersion,
        int $timestamp,
        string $method,
        string $path,
        array $params,
        string $expectedSignature
    ): void {
        $generator = new SignatureGenerator($config);
        $signature = $generator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);

        $this->assertEquals($expectedSignature, $signature);
        $this->assertSame(64, strlen($signature), 'Signature must be a 64-character hex string.');
    }

    /**
     * The canonical parameter string the mobile clients produce, for parameter
     * sets where the ordering or encoding rules are easy to get wrong.
     *
     * Reference: `combinedParameters`/`encode` in APSignedAPIClient's
     * `CoreAPIClient.swift` and core-modules-android's `RequestSigning.kt`.
     */
    public static function canonicalParameterDataProvider(): array
    {
        return [
            'keys sort as strings, not as numbers' => [
                'params' => ['10' => 'a', '9' => 'b'],
                'canonical' => '10=a&9=b',
            ],
            'list indexes keep list order past nine' => [
                'params' => ['tags' => ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k']],
                'canonical' => implode('&', array_map(
                    static fn (int $i, string $v): string => rawurlencode("tags[{$i}]")."={$v}",
                    range(0, 10),
                    ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'],
                )),
            ],
            'lists sort by their own key, not by the expanded key' => [
                'params' => ['a' => ['x'], 'a2' => 'y'],
                'canonical' => rawurlencode('a[0]').'=x&a2=y',
            ],
            'keys are lowercased before sorting' => [
                'params' => ['B' => '2', 'a' => '1'],
                'canonical' => 'a=1&b=2',
            ],
            'nested lists expand recursively' => [
                'params' => ['m' => [['x'], ['y', 'z']]],
                'canonical' => rawurlencode('m[0][0]').'=x&'.rawurlencode('m[1][0]').'=y&'.rawurlencode('m[1][1]').'=z',
            ],
            'objects inside lists are sorted compact json' => [
                'params' => ['m' => [['b' => 2, 'a' => 1]]],
                'canonical' => rawurlencode('m[0]').'='.rawurlencode('{"a":1,"b":2}'),
            ],
            'object keys sort recursively' => [
                'params' => ['o' => ['b' => ['d' => 1, 'c' => 2], 'a' => 3]],
                'canonical' => 'o='.rawurlencode('{"a":3,"b":{"c":2,"d":1}}'),
            ],
            'floats keep their zero fraction' => [
                'params' => ['x' => 1.0, 'y' => 1.5],
                'canonical' => 'x=1.0&y=1.5',
            ],
            'null encodes as an empty value' => [
                'params' => ['x' => null],
                'canonical' => 'x=',
            ],
            'booleans encode as one and zero' => [
                'params' => ['x' => true, 'y' => false],
                'canonical' => 'x=1&y=0',
            ],
            'reserved characters are percent encoded' => [
                'params' => ['a b' => 'c+d/e~f'],
                'canonical' => 'a%20b=c%2Bd%2Fe~f',
            ],
        ];
    }

    #[Test]
    #[DataProvider('canonicalParameterDataProvider')]
    public function it_canonicalises_parameters_the_way_the_clients_do(array $params, string $canonical): void
    {
        $config = [
            'clients' => ['c' => ['client_secret' => 'secret', 'bundle_id' => 'com.example.app']],
            'auth_versions' => [1 => ['signature_template' => ['signature']]],
        ];

        $expected = hash_hmac('sha256', $canonical, 'secret');
        $actual = (new SignatureGenerator($config))->generate('c', 1, 1726669826, 'GET', '/', $params);

        $this->assertSame($expected, $actual);
    }

    #[Test]
    public function it_signs_the_decoded_path_without_turning_plus_into_a_space(): void
    {
        // Clients sign `URL.path`, which percent-decodes but leaves `+` alone.
        $config = [
            'clients' => ['c' => ['client_secret' => 'secret', 'bundle_id' => 'com.example.app']],
            'auth_versions' => [1 => ['signature_template' => ['path']]],
        ];

        $expected = hash_hmac('sha256', '/api/a+b c', 'secret');
        $actual = (new SignatureGenerator($config))->generate('c', 1, 1726669826, 'GET', '/api/a+b%20c', []);

        $this->assertSame($expected, $actual);
    }

    #[Test]
    public function it_throws_exception_for_an_empty_signature_template(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("Signature template for auth version '1' must be a non-empty array.");

        $config = [
            'clients' => ['id' => ['client_secret' => 's', 'bundle_id' => 'b']],
            'auth_versions' => [1 => ['signature_template' => []]],
        ];
        (new SignatureGenerator($config))->generate('id', 1, time(), 'GET', '/', []);
    }

    #[Test]
    public function it_throws_exception_for_unknown_client_id(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("Configuration for client ID 'unknown-client' not found.");

        $config = ['clients' => [], 'auth_versions' => []];
        $generator = new SignatureGenerator($config);
        $generator->generate('unknown-client', 1, time(), 'GET', '/', []);
    }

    #[Test]
    public function it_throws_exception_for_unknown_auth_version(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("Configuration for auth version '999' not found.");

        $config = ['clients' => ['id' => ['client_secret' => 's', 'bundle_id' => 'b']], 'auth_versions' => []];
        $generator = new SignatureGenerator($config);
        $generator->generate('id', 999, time(), 'GET', '/', []);
    }

    #[Test]
    public function it_throws_exception_for_invalid_template_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("Invalid signature template key 'bad-key' for auth version '1'.");

        $config = [
            'clients' => ['id' => ['client_secret' => 's', 'bundle_id' => 'b']],
            'auth_versions' => [1 => ['signature_template' => ['bad-key']]],
        ];
        $generator = new SignatureGenerator($config);
        $generator->generate('id', 1, time(), 'GET', '/', []);
    }
}
