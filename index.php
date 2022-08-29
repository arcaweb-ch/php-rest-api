<?php

/* Including the library */
include_once('lib/lib.php-rest-api.php');

/* Init REST API */
$api = new RestApi(array(
    'return_server_errors' => true,
));

/* Define route with inline response */
$api->get('/', function($api){
    return "PHP REST API works!";
});

/* List all routes */
$api->get('/routes', function($api){
    return $api->getRoutes();
});

/* Routing and pass regex parameters (eg. /test/123456) */
$api->get('/test/([0-9]+)/([0-9]+)', 'parse_multiple_params');

/* Real world example */
$api->get('/test/?', 'get_all');
$api->get('/test/([0-9]+)', 'get');
$api->post('/test/([0-9]+)', 'insert');
$api->put('/test/([0-9]+)', 'update');
$api->delete('/test/([0-9]+)', 'delete');

/* login example and JWT token-> /routes/route.login.php */
$api->post('/login', 'login');

/* Parse the request */
$api->parseRequest();

?>