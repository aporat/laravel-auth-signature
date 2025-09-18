<?php

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
            'default template with array param' => [
                'config' => $baseConfig,
                'clientId' => 'test-client',
                'authVersion' => 1,
                'timestamp' => 1726669826,
                'method' => 'PUT',
                'path' => '/api/users/1',
                'params' => ['user' => ['name' => 'John Doe', 'role' => 'admin']],
                'expectedSignature' => '113e083bbe4a6afb3fadcc7665b92e823103851393bfa1b87d743d6541d9a4ee',
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
