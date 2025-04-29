## REST Micro‑framework v2.0 – Technical Documentation

This document provides a comprehensive overview of the **Micro‑framework REST v2.0**. It covers all features, core classes, functions, and a step‑by‑step Getting Started guide with practical examples. It also demonstrates middleware usage, route parameters, query parameters, regex placeholders, and how to organize your code with `use` and `include` statements.

---

### Table of Contents

1. [Features](#features)
2. [Getting Started](#getting-started)
   - [Installation](#installation)
   - [Basic Usage](#basic-usage)
3. [Core Components](#core-components)
   - [Config](#config)
   - [Response](#response)
   - [Request](#request)
   - [Exceptions](#exceptions)
   - [Validator](#validator)
   - [JWT Helper](#jwt-helper)
   - [Middleware & Route](#middleware--route)
   - [Router](#router)
   - [ErrorHandler](#errorhandler)
   - [RestApi Facade](#restapi-facade)
   - [Controller Auto‑registration](#controller-auto-registration)
4. [Advanced Examples](#advanced-examples)
   - [Defining and Applying Middleware](#defining-and-applying-middleware)
   - [Using Query Parameters](#using-query-parameters)
   - [Regex Placeholders in Routes](#regex-placeholders-in-routes)
   - [Organizing with ](#organizing-with-use-and-include)[`use`](#organizing-with-use-and-include)[ and ](#organizing-with-use-and-include)[`include`](#organizing-with-use-and-include)
5. [Example Project Structure](#example-project-structure)

---

## Features

- **Fluent API** for route definitions with middleware chaining.
- **Onion‑style middleware engine** supporting both callables and classes.
- \*\*Attributes \*\*\`\` on controller methods with optional scanner.
- **Advanced placeholders**: `{param}` or `{param:regex}` (e.g. `{id:\d+}`).
- **Automatic CORS preflight** and reflected CORS configuration.
- **Default security headers**: `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`.
- **JWT helper** for token generation and validation.
- **Centralized error handler** with customizable display of stack traces.
- **No external dependencies**: pure PHP 8.1, strict types, GPL‑3.0.

## Getting Started

### Installation

1. **Download or clone** this framework into your project directory.
2. Ensure PHP **8.1** or later is installed and `strict_types` is enabled.
3. Include the main file in your `index.php` (or front controller):

```php
<?php
declare(strict_types=1);
use App\Config;
use App\RestApi;

require __DIR__ . '/path/to/rest-api.php';
```

#### Apache mod\_rewrite Configuration

Before using the framework, you may want to route all requests under `/api` to the `api.php` front controller. In your Apache configuration or `.htaccess`, enable the rewrite engine and add:

```apache
RewriteEngine On
RewriteRule ^/?api/(.*)$ api.php?u=$1 [QSA,L]
```

### Basic Usage

Create an `index.php` with:

```php
<?php
declare(strict_types=1);

use App\Config;
use App\RestApi;

require __DIR__ . '/lib/RestApi.php';

// 1. Initialize configuration (enable CORS, error display...)
$config = new Config(
    displayErrors: true,
    enableCors: true,
    corsOrigins: ['https://yourdomain.com'],
);

// 2. Instantiate the API
$api = new RestApi($config);

// 3. Define routes
$api->get('ping', fn($req, $p) => ['pong' => true]);

// 4. Run the API
$api->run();
```

Now a `GET /ping` request will return:

```json
{ "pong": true }
```

---

## Core Components

### Config

```php
new Config(
    bool   $displayErrors        = false,
    bool   $enableCors           = false,
    array  $corsOrigins          = ['*'],
    array  $corsMethods          = ['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'],
    array  $corsHeaders          = ['Content-Type','Authorization'],
    bool   $corsAllowCredentials = false,
);
```

Controls error output and CORS behavior.

### Response

- **Constructor**: `Response(int $status = 200, array $headers = [], mixed $body = null)`
- **send()**: emits status, headers, and JSON‑encodes the body.
- **withHeaders(array \$headers)**: returns a new instance merging headers.

```php
return (new Response(201, [], ['id' => $newId]))
    ->withHeaders(['X-Rate-Limit' => '100']);
```

### Request

Provides request data:

- **Properties**: `$method`, `$uri`, `$rawBody`, `$attributes`
- **json()**: parse JSON payload, throws `BadRequestException` if malformed.
- **getHeader(string \$name)**
- **query()**: returns all query string parameters.
- **queryParam(string \$key, mixed \$default = null)**

```php
$data = $req->json();
$page = (int) $req->queryParam('page', 1);
```

### Exceptions

- `HttpException` (base)
- `BadRequestException` (400)
- `UnauthorizedException` (401)
- `ValidationException` (extends 400, carries `errors` array)
- `NotFoundException` (404)
- `MethodNotAllowedException` (405)

Throw these in handlers to send appropriate status codes.

### Validator

```php
$errors = Validator::validate($data, [
    'name' => 'required|string',
    'age'  => 'int',
]);
if ($errors) {
    throw new ValidationException($errors);
}
```

### JWT Helper

```php
$token = Jwt::generate(['sub' => 123, 'exp' => time() + 3600], 'secret-key');
$isValid = Jwt::validate($token, 'secret-key');
```

### Middleware & Route

- **Interface**: implement `MiddlewareInterface::__invoke(Request $request, array $params, callable $next)`.
- **Chaining**: call `$api->get(...)->middleware(AuthMiddleware::class, fn()=>...)`.

```php
class AuthMiddleware implements MiddlewareInterface {
    public function __invoke($req, $params, $next) {
        $token = $req->getHeader('Authorization');
        if (!Jwt::validate($token, 'secret')) {
            throw new UnauthorizedException('Invalid token');
        }
        return $next($req, $params);
    }
}
```

### Router

- **add(\$method, \$pattern, \$handler)**: returns a `Route` for chaining.
- **match(\$method, \$uri)**: returns `[Route, params]` or throws `NotFoundException`.

Placeholders in `$pattern`:

- Simple: `{id}` matches any segment.
- Regex: `{id:\d+}` matches only digits.

### ErrorHandler

Automatically catches exceptions, formats JSON error responses, includes CORS headers.

### RestApi Facade

Shortcut methods to define routes:

```php
$api->get('/users', $handler);
$api->post('/users', $handler);
// put, patch, delete, head, options
```

- **debugRoutes()**: list all registered routes.
- **run()**: handles CORS preflight, routing, middleware pipeline, and sending the response.
- **registerControllers(\$namespace, \$path)**: auto‑scan PHP files for `#[Route]` attributes.

---

## Advanced Examples

### Defining and Applying Middleware

```php
use App\RestApi;
use App\MiddlewareInterface;
use App\UnauthorizedException;

class LoggerMiddleware implements MiddlewareInterface {
    public function __invoke($req, $params, $next) {
        error_log($req->method . ' ' . $req->uri);
        return $next($req, $params);
    }
}

$api = new RestApi();
$api->get('secure/data', fn($r,$p) => ['data'=>42])
    ->middleware(LoggerMiddleware::class, AuthMiddleware::class);
```

### Using Query Parameters

```php
$api->get('search', function($req,$p) {
    $term = $req->queryParam('term', '');
    $limit = (int) $req->queryParam('limit', 10);
    return ['results' => searchDatabase($term, $limit)];
});
```

### Regex Placeholders in Routes

```php
$api->get('items/{item_id:\\d+}', function($req, $p) {
    // $p['item_id'] is guaranteed numeric
    return getItemById((int)$p['item_id']);
});
```

### Organizing with `use` and `include`

```php
<?php
declare(strict_types=1);
use App\Config;
use App\RestApi;

require __DIR__ . '/lib/RestApi.php';

$config = new Config(enableCors: true);
$api = new RestApi($config);

// Split routes into separate files
include __DIR__ . '/routes/ping.php';
include __DIR__ . '/routes/users.php';

$api->run();
```

In `routes/users.php`:

```php
use App\RestApi;
use App\Response;

/** @var RestApi $api */
$api->get('users', function($req, $p) {
    return ['users' => ['Alice','Bob']];
});
```

---

## Example Project Structure

```
project/
├── lib/
│   └── RestApi.php            # framework core
├── routes/
│   ├── ping.php
│   └── users.php
└── public/
    └── index.php             # front controller
```

---

This documentation covers all features, core classes, and provides practical examples to get you started quickly. Enjoy building RESTful APIs with this lightweight micro‑framework!

