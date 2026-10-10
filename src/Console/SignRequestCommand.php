<?php

declare(strict_types=1);

namespace Aporat\AuthSignature\Console;

use const JSON_ERROR_NONE;

use Aporat\AuthSignature\Client\RequestSigner;
use Aporat\AuthSignature\Exceptions\InvalidConfigurationException;
use GuzzleHttp\Psr7\Request as Psr7Request;
use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\Console\Output\OutputInterface;

use function array_filter;
use function array_keys;
use function array_map;
use function array_values;
use function count;
use function ctype_digit;
use function escapeshellarg;
use function explode;
use function implode;
use function is_array;
use function is_string;
use function json_decode;
use function json_last_error;
use function ltrim;
use function preg_match;
use function rawurldecode;
use function rawurlencode;
use function rtrim;
use function sprintf;
use function str_contains;
use function strtoupper;
use function time;

/**
 * Prints the X-Auth-* headers (or a curl command) for a request, signed with
 * the configured client secret. The secret itself is never printed.
 */
class SignRequestCommand extends Command
{
    protected $signature = 'auth-signature:sign
        {method : HTTP method, e.g. GET or POST}
        {url : Full URL, or a path resolved against app.url}
        {--client= : Client id (optional when exactly one client is configured)}
        {--auth-version= : Auth version (defaults to the client\'s min_auth_level, else the highest configured version)}
        {--data= : JSON request body}
        {--form=* : Form field as key=value (repeatable); sent form-urlencoded}
        {--query=* : Query parameter as key=value (repeatable); appended to the URL}
        {--timestamp= : Unix timestamp to sign with (defaults to now)}
        {--curl : Print a ready-to-run curl command instead of the headers}
        {--debug : Also print the canonical string being signed (same as -v)}';

    protected $description = 'Sign a request with a configured client and print its X-Auth-* headers';

    public function handle(RequestSigner $signer, Repository $config): int
    {
        try {
            $clientId = $this->clientId($config);
            $authVersion = $this->intOption('auth-version') ?? $signer->defaultAuthVersion($clientId);
            $timestamp = $this->intOption('timestamp') ?? time();
            $request = $this->buildRequest($config);

            $signer->assertCanSign($clientId, $authVersion);
            $headers = $signer->headers($request, $clientId, $authVersion, null, $timestamp);
        } catch (InvalidConfigurationException|InvalidArgumentException $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        if ($this->option('debug') || $this->output->isVerbose()) {
            $this->printDebug($signer, $request, $clientId, $authVersion, $timestamp);
        }

        $lines = $this->option('curl')
            ? [$this->curl($request, $headers)]
            : array_map(fn (string $name, string $value) => $name.': '.$value, array_keys($headers), $headers);

        foreach ($lines as $line) {
            $this->output->writeln($line, OutputInterface::OUTPUT_RAW);
        }

        return self::SUCCESS;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function clientId(Repository $config): string
    {
        $client = $this->option('client');

        if (is_string($client) && $client !== '') {
            return $client;
        }

        $clients = $config->get('auth-signature.clients');
        $ids = is_array($clients) ? array_map('strval', array_keys($clients)) : [];

        if (count($ids) === 1) {
            return $ids[0];
        }

        throw new InvalidArgumentException(sprintf(
            'Pass --client. Configured clients: %s.',
            $ids === [] ? 'none' : implode(', ', $ids)
        ));
    }

    /**
     * @throws InvalidArgumentException
     */
    private function intOption(string $name): ?int
    {
        $value = $this->option($name);

        if ($value === null || $value === '') {
            return null;
        }

        if (! is_string($value) || ! ctype_digit($value) || (int) $value <= 0) {
            throw new InvalidArgumentException(sprintf('--%s must be a positive integer.', $name));
        }

        return (int) $value;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function buildRequest(Repository $config): Psr7Request
    {
        $method = strtoupper($this->stringArgument('method'));

        if (! preg_match('/^[A-Z]+$/', $method)) {
            throw new InvalidArgumentException('The method must be a word such as GET or POST.');
        }

        $url = $this->url($this->stringArgument('url'), $config);
        $query = $this->encodePairs($this->listOption('query'), '--query');

        if ($query !== '') {
            $url .= (str_contains($url, '?') ? '&' : '?').$query;
        }

        $data = $this->option('data');
        $form = $this->listOption('form');

        if (is_string($data) && $data !== '' && $form !== []) {
            throw new InvalidArgumentException('Use either --data or --form, not both.');
        }

        if (is_string($data) && $data !== '') {
            json_decode($data);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidArgumentException('--data must be valid JSON.');
            }

            return new Psr7Request($method, $url, ['Content-Type' => 'application/json'], $data);
        }

        if ($form !== []) {
            return new Psr7Request(
                $method,
                $url,
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                $this->encodePairs($form, '--form')
            );
        }

        return new Psr7Request($method, $url);
    }

    private function stringArgument(string $name): string
    {
        $value = $this->argument($name);

        return is_string($value) ? $value : '';
    }

    private function url(string $url, Repository $config): string
    {
        if (preg_match('#^https?://#i', $url)) {
            return $url;
        }

        $base = $config->get('app.url');
        $base = is_string($base) && $base !== '' ? rtrim($base, '/') : 'http://localhost';

        return $base.'/'.ltrim($url, '/');
    }

    /**
     * @return list<string>
     */
    private function listOption(string $name): array
    {
        $values = $this->option($name);

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }

    /**
     * Encodes key=value pairs as an RFC 3986 query string. Keys may use
     * bracket syntax (tags[]=a, filter[status]=open).
     *
     * @param  list<string>  $pairs
     *
     * @throws InvalidArgumentException
     */
    private function encodePairs(array $pairs, string $option): string
    {
        $encoded = [];

        foreach ($pairs as $pair) {
            [$key, $value] = str_contains($pair, '=') ? explode('=', $pair, 2) : [$pair, ''];

            if ($key === '') {
                throw new InvalidArgumentException(sprintf('%s expects key=value, got "%s".', $option, $pair));
            }

            $encoded[] = rawurlencode($key).'='.rawurlencode($value);
        }

        return implode('&', $encoded);
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function curl(RequestInterface $request, array $headers): string
    {
        $parts = ['curl -X '.escapeshellarg($request->getMethod()).' '.escapeshellarg((string) $request->getUri())];

        $contentType = $request->getHeaderLine('Content-Type');

        if ($contentType !== '') {
            $headers['Content-Type'] = $contentType;
        }

        foreach ($headers as $name => $value) {
            $parts[] = '-H '.escapeshellarg($name.': '.$value);
        }

        $body = (string) $request->getBody();

        if ($body !== '') {
            $parts[] = '--data-raw '.escapeshellarg($body);
        }

        return implode(" \\\n  ", $parts);
    }

    private function printDebug(RequestSigner $signer, RequestInterface $request, string $clientId, int $authVersion, int $timestamp): void
    {
        $this->output->writeln('Method: '.$request->getMethod(), OutputInterface::OUTPUT_RAW);
        $this->output->writeln('URL: '.$request->getUri(), OutputInterface::OUTPUT_RAW);
        $this->output->writeln('Path signed: '.rawurldecode($signer->path($request)), OutputInterface::OUTPUT_RAW);
        $this->output->writeln('String to sign: '.$signer->stringToSign($request, $clientId, $authVersion, $timestamp), OutputInterface::OUTPUT_RAW);
        $this->output->writeln('', OutputInterface::OUTPUT_RAW);
    }
}
