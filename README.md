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

### Define your routes
```php
$api->get('', function(){
    return "It works!";
});
```

### Use callback functions
```php
function my_callback(){
    return 'Awesome!';
}
$api->get('awesome', 'my_callback');
```

### Example: Use API methods
**$api** is passed to route callback functions to make public methods always available.
```php
$api->get('routes', function($api){
    return $api->getRoutes();
});
```

### Example: Routing with REGEX and get dynamic parameters
```php
$api->get('test/([0-9]+)/([0-9]+)', function ($api){

    $matches = $api->getMatches();
    return $matches;

});
```
The above example will return an array with two matching digits specified in the URL.

### Route auto-inclusion
Route files will be automatically included if exists based on first level URI path. For example, when **/foo/** route is defined and called, **routes/route.foo.php** will be automatically included.

### More examples with callback
This example shows how multiple HTTP methods can be routed to different callback functions. You can find them in the example source as well.
```php
$api->get('test/?', 'get_all');
$api->get('test/([0-9]+)', 'get');
$api->post('test/([0-9]+)', 'insert');
$api->put('test/([0-9]+)', 'update');
$api->delete('test/([0-9]+)', 'delete');
```

### Login endopoint example with embedded JWT token generator:
Login example with JWT token-> /routes/route.login.php
```php
$api->post('login', 'login');
```

### Parse the request
This will process the request
```php
$api->parseRequest();
```
