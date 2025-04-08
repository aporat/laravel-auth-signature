<?php

namespace Aporat\AuthSignature\Tests;

use Aporat\AuthSignature\SignatureGenerator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class SignatureGeneratorTest extends TestCase
{
    protected SignatureGenerator $signatureGenerator;

    protected function setUp(): void
    {
        parent::setUp();

        // Initialize SignatureGenerator with a test config
        $this->signatureGenerator = new SignatureGenerator([
            'clients' => [
                'client-id' => [
                    'client_secret' => 'secret',
                    'bundle_id' => 'com.test.app',
                ],
            ],
            'auth_versions' => [
                1 => [
                    'secret' => 'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ',
                    'state' => 'RSA2048',
                ],
            ],
        ]);
    }

    #[Test]
    public function it_generates_signature_with_default_template_order(): void
    {
        $clientId = 'client-id';
        $authVersion = 1;
        $timestamp = 1698777600; // Fixed timestamp for reproducibility
        $method = 'GET';
        $path = '/test';
        $params = ['key' => 'value', 'foo' => 'bar'];

        $signature = $this->signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);

        // Expected signature computation
        ksort($params);
        $signatureString = implode('&', [
            'foo='.rawurlencode('bar'),
            'key='.rawurlencode('value'),
        ]);
        $template = urldecode('com.test.app').
            '1698777600'.
            'client-id'.
            'RSA2048'.
            '1'.
            'GET'.
            $signatureString.
            urldecode('/test');
        $expectedSignature = hash_hmac('sha256', $template, 'secret'.'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ');

        $this->assertEquals($expectedSignature, $signature);
        $this->assertEquals(64, strlen($signature), 'Signature should be a 64-character SHA-256 hash');
    }

    #[Test]
    public function it_generates_signature_with_custom_template_order(): void
    {
        $signatureGenerator = new SignatureGenerator([
            'clients' => [
                'client-id' => [
                    'client_secret' => 'secret',
                    'bundle_id' => 'com.test.app',
                ],
            ],
            'auth_versions' => [
                1 => [
                    'secret' => 'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ',
                    'state' => 'RSA2048',
                    'signature_template' => [
                        'method',
                        'path',
                        'client_id',
                        'timestamp',
                        'auth_version',
                        'signature',
                        'bundle_id',
                    ],
                ],
            ],
        ]);

        $clientId = 'client-id';
        $authVersion = 1;
        $timestamp = 1698777600;
        $method = 'POST';
        $path = '/api/test';
        $params = ['key2' => 'value2', 'key' => 'value'];

        $signature = $signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);

        // Exact template computation
        $signatureString = 'key=value&key2=value2';
        $template = 'POST'.'/api/test'.'client-id'.'16987776001'.$signatureString.'com.test.app';
        $expectedSignature = hash_hmac('sha256', $template, 'secret'.'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ');

        $this->assertEquals($expectedSignature, $signature);
        $this->assertEquals(64, strlen($signature), 'Signature should be a 64-character SHA-256 hash');
    }

    #[Test]
    public function it_generates_signature_with_empty_params(): void
    {
        $clientId = 'client-id';
        $authVersion = 1;
        $timestamp = 1698777600;
        $method = 'GET';
        $path = '/empty';
        $params = [];

        $signature = $this->signatureGenerator->generate($clientId, $authVersion, $timestamp, $method, $path, $params);

        // Expected signature with no params
        $template = urldecode('com.test.app').
            '1698777600'.
            'client-id'.
            'RSA2048'.
            '1'.
            'GET'.
            ''. // Empty signature string
            urldecode('/empty');
        $expectedSignature = hash_hmac('sha256', $template, 'secret'.'oQqx4teM9Kaf0EZUeSuqreNzHOTz1rXZ');

        $this->assertEquals($expectedSignature, $signature);
    }
}
