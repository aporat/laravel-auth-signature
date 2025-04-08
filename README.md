# Laravel Auth Signature

[![Latest Stable Version](https://img.shields.io/packagist/v/aporat/laravel-auth-signature.svg?style=flat-square&logo=composer)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![Monthly Downloads](https://img.shields.io/packagist/dm/aporat/laravel-auth-signature.svg?style=flat-square&logo=composer)](https://packagist.org/packages/aporat/laravel-auth-signature)
[![Codecov](https://img.shields.io/codecov/c/github/aporat/laravel-auth-signature?style=flat-square)](https://codecov.io/github/aporat/laravel-auth-signature)
[![Laravel Version](https://img.shields.io/badge/Laravel-12.x-orange.svg?style=flat-square)](https://laravel.com/docs/12.x)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/aporat/laravel-auth-signature/ci.yml?style=flat-square)
[![License](https://img.shields.io/packagist/l/aporat/laravel-auth-signature.svg?style=flat-square)](https://github.com/aporat/laravel-auth-signature/blob/master/LICENSE)

## Requirements
- **PHP**: 8.4 or higher
- **Laravel**: 10.x, 11.x,  12.x

## Installation
Install the package via [Composer](https://getcomposer.org/):

```bash
composer require aporat/laravel-auth-signature
```

The service provider (`AuthSignatureServiceProvider`) is automatically registered via Laravel’s package discovery. If auto-discovery is disabled, add it to `config/app.php`:

```php
'providers' => [
    // ...
    Aporat\AuthSignature\Laravel\AuthSignatureServiceProvider::class,
],
```

Publish the configuration file:

```bash
php artisan vendor:publish --provider="Aporat\AuthSignature\Laravel\AuthSignatureServiceProvider" --tag="config"
```

This copies `auth-signature.php` to your `config/` directory.

## Configuration
