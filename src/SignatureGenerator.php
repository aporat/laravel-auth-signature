<?php

namespace Aporat\AuthSignature;

use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;

class SignatureGenerator
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function generate(string $clientId, int $authVersion, int $timestamp, string $method, string $path, array $params): string
    {
        ksort($params);
        $path = urldecode($path);

        $signature = [];
        foreach ($params as $key => $value) {

            if (is_array($value)) {
                $signature[] = urlencode(strtolower($key)).'='.rawurlencode(json_encode($value, JSON_UNESCAPED_UNICODE));
            } else {
                $signature[] = urlencode(strtolower($key)).'='.rawurlencode($value);
            }
        }

        $signatureString = implode('&', $signature);

        $clientSecret = $this->config['clients'][$clientId]['client_secret'];
        $bundleId = $this->config['clients'][$clientId]['bundle_id'];

        if (! empty($this->config['auth_versions'][$authVersion]['secret'])) {
            $clientSecret .= $this->config['auth_versions'][$authVersion]['secret'];
        }

        $state = $this->config['auth_versions'][$authVersion]['state'] ?? '';

        // Define available components
        $components = [
            'bundle_id' => urldecode($bundleId),
            'timestamp' => (string) $timestamp,
            'client_id' => $clientId,
            'state' => $state,
            'auth_version' => (string) $authVersion,
            'method' => $method,
            'signature' => $signatureString,
            'path' => urldecode($path),
        ];

        // Get the template order from config, defaulting to original order
        $templateOrder = $this->config['auth_versions'][$authVersion]['signature_template'] ?? [
            'bundle_id',
            'timestamp',
            'client_id',
            'state',
            'auth_version',
            'method',
            'signature',
            'path',
        ];

        // Assemble the template based on the configured order
        $template = '';
        foreach ($templateOrder as $key) {

            if (! isset($components[$key])) {
                throw new InvalidConfigurationException("Invalid signature template key '$key' for auth version '$authVersion'.");
            }

            $template .= $components[$key];
        }

        return hash_hmac('sha256', $template, $clientSecret);
    }
}
