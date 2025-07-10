<?php

/**
 * PHP REST API Class
 *
 * A simple PHP REST Micro‑framework
 *
 * PHP version 8.1
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author      Lorenzo Conti <l.conti@arcaweb.ch>
 * @copyright   2025 Arcaweb
 * @license     https://www.gnu.org/licenses/gpl-3.0.txt
 * @version     SVN: 2.0.0
 * @link        https://github.com/arcaweb-ch/php-rest-api
 */

declare(strict_types=1);

namespace App;

use Attribute;
use DateTimeImmutable;
use JsonException;
use ReflectionClass;
use ReflectionMethod;
use Throwable;

/* -----------------------------------------------------------
 | Config                                                     |
 -----------------------------------------------------------*/
final class Config
{
    public function __construct(
        public readonly bool   $displayErrors        = false,
        public readonly bool   $enableCors           = false,
        public readonly array  $corsOrigins          = ['*'],
        public readonly array  $corsMethods          = ['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'],
        public readonly array  $corsHeaders          = ['Content-Type','Authorization'],
        public readonly bool   $corsAllowCredentials = false,
    ) {}
}

/* -----------------------------------------------------------
 | Response                                                   |
 -----------------------------------------------------------*/
final class Response
{
    private const SEC_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy'        => 'same-origin',
        'X-Frame-Options'        => 'DENY',
        'Content-Type'           => 'application/json; charset=utf-8', // aggiunto
    ];

    public function __construct(
        public readonly int   $status  = 200,
        public readonly array $headers = self::SEC_HEADERS,
        public readonly mixed $body    = null,
    ) {}

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header($k . ': ' . $v);
        }
        if ($this->body !== null && $_SERVER['REQUEST_METHOD'] !== 'HEAD') {
            try {
                echo is_string($this->body)
                    ? $this->body
                    : json_encode($this->body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            } catch (JsonException) {
                echo (string) $this->body;
            }
        }
    }

    public function withHeaders(array $headers): self
    {
        return new self($this->status, array_merge($this->headers, $headers), $this->body);
    }
}

/* -----------------------------------------------------------
 | Request                                                    |
 -----------------------------------------------------------*/
final class Request
{
    public readonly string $method;
    public readonly string $uri;
    public readonly string $rawBody;
    public array $attributes = [];
    private ?array $jsonCache = null;

    public function __construct()
    {
        $this->method  = strtolower($_SERVER['REQUEST_METHOD'] ?? 'get');
        $this->uri = trim($this->parseUri(), '/');
        $this->rawBody = file_get_contents('php://input');
    }

    private function parseUri(): string
    {
        // Migliore parsing dell'URI per evitare problemi con query parameters
        $uri = $_GET['u'] ?? '';
        if (empty($uri)) {
            $requestUri = $_SERVER['REQUEST_URI'] ?? '';
            $scriptName = dirname($_SERVER['SCRIPT_NAME']);
            if ($scriptName !== '/') {
                $requestUri = substr($requestUri, strlen($scriptName));
            }
            $uri = parse_url($requestUri, PHP_URL_PATH) ?? '';
            $uri = ltrim($uri, '/');
        }
        return $uri;
    }

    public function json(): array
    {
        if ($this->jsonCache !== null) return $this->jsonCache;

        $ct = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
        if (!str_starts_with($ct, 'application/json')) return $this->jsonCache = [];
        if ($this->rawBody === '') return $this->jsonCache = [];

        try {
            return $this->jsonCache = json_decode($this->rawBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new BadRequestException('Malformed JSON: ' . $e->getMessage());
        }
    }

    public function getHeader(string $name): ?string
    {
        $key = 'HTTP_' . str_replace('-', '_', strtoupper($name));
        return $_SERVER[$key] ?? null;
    }

    public function query(): array
    {
        $qs = $_GET;
        unset($qs['u']);
        return $qs;
    }

    public function queryParam(string $key, mixed $default = null): mixed
    {
        return $_GET[$key] ?? $default;
    }
}

/* -----------------------------------------------------------
 | Exceptions                                                 |
 -----------------------------------------------------------*/
class HttpException extends \RuntimeException { public function __construct(string $m,int $c){parent::__construct($m,$c);} }
class BadRequestException extends HttpException { public function __construct(string $m){parent::__construct($m,400);} }
class UnauthorizedException extends HttpException { public function __construct(string $m){parent::__construct($m,401);} }
class ForbiddenException extends HttpException { public function __construct(string $m){parent::__construct($m,403);} }
class ValidationException extends BadRequestException { public function __construct(public array $errors){parent::__construct('Validation failed');} }
class NotFoundException extends HttpException { public function __construct(string $m){parent::__construct($m,404);} }
class MethodNotAllowedException extends HttpException { public function __construct(string $m){parent::__construct($m,405);} }

/* -----------------------------------------------------------
 | Validator                                                  |
 -----------------------------------------------------------*/
final class Validator
{
    public static function validate(array $data, array $rules): array
    {
        $errors = [];
        foreach ($rules as $key => $ruleString) {
            $rulesArr = array_map('trim', explode('|', $ruleString));
            $exists   = array_key_exists($key, $data);

            if (in_array('required', $rulesArr, true) && !$exists) {
                $errors[] = "$key is required";
                continue;
            }
            if (!$exists) {
                continue;
            }

            $value = $data[$key];
            foreach ($rulesArr as $rule) {
                // split rule name and parameter (e.g. min:8)
                [$name, $param] = array_pad(explode(':', $rule, 2), 2, null);

                switch ($name) {
                    case 'int':
                        if (!filter_var($value, FILTER_VALIDATE_INT) && !is_int($value)) {
                            $errors[] = "$key must be int";
                        }
                        break;
                    case 'string':
                        if (!is_string($value)) {
                            $errors[] = "$key must be string";
                        }
                        break;
                    case 'bool':
                        if (!is_bool($value)) {
                            $errors[] = "$key must be bool";
                        }
                        break;
                    case 'email':
                        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            $errors[] = "$key invalid email";
                        }
                        break;
                    case 'url':
                        if (!filter_var($value, FILTER_VALIDATE_URL)) {
                            $errors[] = "$key invalid url";
                        }
                        break;
                    case 'ip':
                        if (!filter_var($value, FILTER_VALIDATE_IP)) {
                            $errors[] = "$key invalid ip";
                        }
                        break;
                    case 'array':
                        if (!is_array($value)) {
                            $errors[] = "$key must be array";
                        }
                        break;
                    case 'json':
                        if (
                            !is_string($value)
                            || !json_decode($value, true, 512, JSON_THROW_ON_ERROR)
                        ) {
                            $errors[] = "$key invalid json";
                        }
                        break;
                    case 'date':
                        if (!self::dt((string)$value, 'Y-m-d')) {
                            $errors[] = "$key invalid date";
                        }
                        break;
                    case 'time':
                        if (!self::dt((string)$value, 'H:i:s')) {
                            $errors[] = "$key invalid time";
                        }
                        break;
                    case 'datetime':
                        if (!self::dt((string)$value, 'Y-m-d H:i:s')) {
                            $errors[] = "$key invalid datetime";
                        }
                        break;
                    case 'min':
                        $min = (int)$param;
                        if (is_string($value) && mb_strlen($value) < $min) {
                            $errors[] = "$key minimum length is $min";
                        } elseif (is_array($value) && count($value) < $min) {
                            $errors[] = "$key minimum items is $min";
                        }
                        break;
                    case 'max':
                        $max = (int)$param;
                        if (is_string($value) && mb_strlen($value) > $max) {
                            $errors[] = "$key maximum length is $max";
                        } elseif (is_array($value) && count($value) > $max) {
                            $errors[] = "$key maximum items is $max";
                        }
                        break;
                }
            }
        }
        return $errors;
    }

    private static function dt(string $v, string $fmt): bool
    {
        $d = DateTimeImmutable::createFromFormat($fmt, $v);
        return $d !== false && $d->format($fmt) === $v;
    }
}

/* -----------------------------------------------------------
 | JWT helper                                                 |
 -----------------------------------------------------------*/
final class Jwt
{
    private static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    private static function decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function generate(array $payload, string $secret): string
    {
        $header  = self::encode(json_encode(['alg' => 'HS256','typ' => 'JWT'], JSON_THROW_ON_ERROR));
        $body    = self::encode(json_encode($payload, JSON_THROW_ON_ERROR));
        $sign    = self::encode(hash_hmac('sha256', "$header.$body", $secret, true));
        return "$header.$body.$sign";
    }

    public static function validate(string $jwt, string $secret): bool
    {
        $parts = explode('.', $jwt, 3);
        if (count($parts) !== 3) {
            return false;
        }
        [$header64, $body64, $signature64] = $parts;
        $header = json_decode(self::decode($header64), true, 512, JSON_THROW_ON_ERROR);
        if (($header['alg'] ?? '') !== 'HS256') {
            return false;
        }
        $expected = self::encode(hash_hmac('sha256', "$header64.$body64", $secret, true));
        if (!hash_equals($expected, $signature64)) {
            return false;
        }
        $claims = json_decode(self::decode($body64), true, 512, JSON_THROW_ON_ERROR);
        return !isset($claims['exp']) || $claims['exp'] >= time();
    }
}

/* -----------------------------------------------------------
 | Middleware & Route                                         |
 -----------------------------------------------------------*/
interface MiddlewareInterface
{
    public function __invoke(Request $request, array $params, callable $next);
}

final class Route
{
    private array $middleware = [];

    public function __construct(
        public readonly string $method,
        public readonly string $pattern,
        public readonly \Closure $handler  // <- torna a \Closure
    ) {}

    public function middleware(callable|string ...$mw): self
    {
        $this->middleware = [...$this->middleware, ...$mw];
        return $this;
    }

    public function getMiddleware(): array
    {
        return $this->middleware;
    }
}

/*------------------------------------------------------------
 | Attribute for controller methods                          |
 -----------------------------------------------------------*/
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class RouteAttr
{
    public function __construct(
        public readonly string $method,
        public readonly string $path
    ) {}
}

/* -----------------------------------------------------------
 | Router                                                     |
 -----------------------------------------------------------*/
final class Router
{
    /** @var array<string,list<Route>> */
    private array $routes = [
        'get' => [], 'post' => [], 'put' => [], 'patch' => [],
        'delete' => [], 'head' => [], 'options' => []
    ];

    public function getDebugRoutes(): array
    {
        $out = [];
        foreach ($this->routes as $method => $routes) {
            foreach ($routes as $route) {
                $out[] = strtoupper($method) . ' ' . $route->pattern;
            }
        }
        return $out;
    }

    public function add(string $method, string $pattern, callable $handler): Route
    {
        $m = strtolower($method);
        // Converti callable in Closure se necessario
        $closureHandler = $handler instanceof \Closure ? $handler : \Closure::fromCallable($handler);
        $route = new Route($m, $pattern, $closureHandler);
        $this->routes[$m][] = $route;
        return $route;
    }

    /**
     * Match request to a Route and extract params
     * @return array{0:Route,1:array<string,string>}
     */
    public function match(string $method, string $uri): array
    {
        $m = $method === 'head' ? 'get' : strtolower($method);
        foreach ($this->routes[$m] ?? [] as $route) {
            $regex = '#^' . preg_replace_callback(
                '/\\{([\w]+)(?::([^}]+))?\\}/',
                static fn($m) => '(?P<' . $m[1] . '>' . ($m[2] ?? '[^/]+') . ')',
                $route->pattern
            ) . '$#';
            if (preg_match($regex, $uri, $matches)) {
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                return [$route, $params];
            }
        }
        throw new NotFoundException('Route not found: ' . $uri);
    }
}

/* -----------------------------------------------------------
 | ErrorHandler                                               |
 -----------------------------------------------------------*/
final class ErrorHandler
{
    public function __construct(private readonly Config $cfg)
    {
        set_exception_handler([$this, 'handle']);
        set_error_handler([$this, 'handleError']);
    }

    public function handleError(int $severity, string $message, string $file = '', int $line = 0): bool
    {
        // Converti gli errori PHP in eccezioni per gestirli in modo uniforme
        if (error_reporting() & $severity) {
            throw new \ErrorException($message, 0, $severity, $file, $line);
        }
        return false;
    }

    public function handle(Throwable $t): never
    {
        // Pulisci qualsiasi output precedente
        if (ob_get_level()) {
            ob_clean();
        }
        
        // Assicurati che l'header Content-Type sia JSON
        header('Content-Type: application/json; charset=utf-8');
        
        $code = $t instanceof HttpException ? $t->getCode() : 500;
        $body = ['error' => $t->getMessage(), 'code' => $code];
        if ($t instanceof ValidationException) {
            $body['validation'] = $t->errors;
        }
        if ($this->cfg->displayErrors && $code === 500) {
            $body['trace'] = $t->getTrace();
            $body['file'] = $t->getFile();
            $body['line'] = $t->getLine();
        }
        (new Response($code, body: $body))
            ->withHeaders($this->corsHeaders())
            ->send();
        exit;
    }

    public function corsHeaders(): array
    {
        if (!$this->cfg->enableCors) {
            return [];
        }
        $originHeader = $_SERVER['HTTP_ORIGIN'] ?? '';
        $origin = '';
        if (in_array('*', $this->cfg->corsOrigins, true)) {
            $origin = '*';
        } elseif ($originHeader !== '' && in_array($originHeader, $this->cfg->corsOrigins, true)) {
            $origin = $originHeader;
        }
        $hdr = [
            'Access-Control-Allow-Methods'     => implode(',', $this->cfg->corsMethods),
            'Access-Control-Allow-Headers'     => implode(',', $this->cfg->corsHeaders),
            'Access-Control-Allow-Credentials' => $this->cfg->corsAllowCredentials ? 'true' : 'false',
        ];
        if ($origin !== '') {
            $hdr['Access-Control-Allow-Origin'] = $origin;
        }
        return $hdr;
    }
}

/* -----------------------------------------------------------
 | Public Facade                                              |
 -----------------------------------------------------------*/
final class RestApi
{
    private Router  $router;
    private Request $request;
    private Config  $cfg;

    public function __construct(Config|array|null $config = null)
    {
        $this->cfg     = $config instanceof Config ? $config : new Config(...($config ?? []));
        $this->router  = new Router();
        $this->request = new Request();
        new ErrorHandler($this->cfg);
    }

    /* Shortcut methods */
    public function get(string $pattern, callable $handler): Route    { return $this->router->add('GET',    $pattern, $handler); }
    public function post(string $pattern, callable $handler): Route   { return $this->router->add('POST',   $pattern, $handler); }
    public function put(string $pattern, callable $handler): Route    { return $this->router->add('PUT',    $pattern, $handler); }
    public function patch(string $pattern, callable $handler): Route  { return $this->router->add('PATCH',  $pattern, $handler); }
    public function delete(string $pattern, callable $handler): Route { return $this->router->add('DELETE', $pattern, $handler); }
    public function head(string $pattern, callable $handler): Route   { return $this->router->add('HEAD',   $pattern, $handler); }
    public function options(string $pattern, callable $handler): Route{ return $this->router->add('OPTIONS',$pattern,$handler); }

    public function debugRoutes(): array
    {
        return $this->router->getDebugRoutes();
    }

    public function run(): void
    {
        // Improved CORS preflight handling
        if ($this->request->method === 'options') {
            try {
                $this->router->match('OPTIONS', $this->request->uri);
            } catch (NotFoundException) {
                // Always send CORS headers for preflight, even if route not found
                $headers = $this->corsHeaders();
                $headers['Access-Control-Max-Age'] = '86400'; // Cache preflight for 24h
                (new Response(200, $headers))->send();
                return;
            }
        }

        try {
            [$route, $params] = $this->router->match($this->request->method, $this->request->uri);
        } catch (NotFoundException $e) {
            // Ensure CORS headers are sent even for 404s
            (new Response(404, $this->corsHeaders(), ['error' => $e->getMessage(), 'code' => 404]))->send();
            return;
        }

        // build middleware pipeline
        $handler = function(Request $req, array $p) use ($route) {
            return ($route->handler)($req, $p);
        };
        foreach (array_reverse($route->getMiddleware()) as $mw) {
            $next = $handler;
            $handler = is_string($mw)
                ? fn($req, $p) => (new $mw())($req, $p, $next)
                : fn($req, $p) => $mw($req, $p, $next);
        }

        try {
            $response = $handler($this->request, $params);
            if (!$response instanceof Response) {
                $response = new Response(body: $response);
            }
        } catch (Throwable $e) {
            // Let ErrorHandler manage exceptions, but ensure it has access to CORS headers
            throw $e;
        }

        $response
            ->withHeaders($this->corsHeaders())
            ->send();
    }

    private function corsHeaders(): array
    {
        // reuse ErrorHandler logic
        return (new ErrorHandler($this->cfg))
            ->{/**/ 'corsHeaders'}();
    }

    /**
     * Optional: auto-register controllers via #[Route]
     */
    public function registerControllers(string $namespace, string $path): void
    {
        foreach (glob($path . '/*.php') as $file) {
            require_once $file;
            $class = $namespace . '\\' . basename($file, '.php');
            if (!class_exists($class)) continue;
            $ref = new ReflectionClass($class);
            foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                foreach ($method->getAttributes(RouteAttr::class) as $attr) {
                    /** @var RouteAttr $ra */
                    $ra = $attr->newInstance();
                    $this->router->add($ra->method, $ra->path, [$class, $method->getName()]);
                }
            }
        }
    }
}

?>
