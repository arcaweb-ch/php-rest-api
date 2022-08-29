# php-rest-api

Inspired by express.js I created this tiny **PHP class** to make it easier developing basic **REST APIs**, by handling common API needs, such as:

- Easy routing for CRUD operations (GET, POST, PUT, DELETE)
- Request data validation and error reporting
- Server error handling and reporting option
- HTTP status codes management
- Consistent JSON outputs
- Error logging

### Requirements
- PHP 7.0 >
- Setup a rewrite rule to address any request, eg:
```
RewriteRule ^/php-rest-api/(.*)$ /php-rest-api/index.php?u=/$1 [NC]
```

### Include the library
```php
include_once('lib/lib.php-rest-api.php');
```

### Create the API instance
Override config parameters by passing them as array
```php
$api = new RestApi(array(
    'return_server_errors' => true,
));
```

### Define your routes and callbacks (inline in this case)
```php
$api->get('/', function(){
    return "It works!";
});
```

### Example: List all routes
**$api** is always passed to routing functions to make public methods always available.
```php
$api->get('/routes', function($api){
    return $api->getRoutes();
});
```

### Example: Routing and pass regex parameters (eg. /test/123456)
When **/test** endpoint URL is called, the api manager looks for **routes/route.test.php** and auto-includes it if exists, this way it doesn't have to be included manually.
```php
$api->get('/test/([0-9]+)/([0-9]+)', 'parse_multiple_params');
```
Defined URLs are REGEX patterns in which multiple matching parameters can be specified, to see how they are parsed please check test route file.

### More examples:
Multiple request methods, all callback functions are defined in **routes/route.test.php**
```php
$api->get('/test/?', 'get_all');
$api->get('/test/([0-9]+)', 'get');
$api->post('/test/([0-9]+)', 'insert');
$api->put('/test/([0-9]+)', 'update');
$api->delete('/test/([0-9]+)', 'delete');
```

Login example with JWT token-> /routes/route.login.php
```php
$api->post('/login', 'login');
```

### Parse the request
```php
$api->parseRequest();
```
