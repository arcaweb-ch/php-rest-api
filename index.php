<?php

/**
 * 
 * This is an example use of PHP Rest API Class.
 * @author: Lorenzo Conti
 * 
 */

/* Class inclusion */

include_once('lib/lib.php-rest-api.php');

/* Init API instance */

$api = new RestApi(array(

    'return_server_errors' => true,

));

/* Define base route with inline response */

$api->get('', function($api){

    return "It works!";

});

/* This route will return all defined routes */

$api->get('routes', function($api){

    return $api->getRoutes();

});

/* This returns an array with passed parameters matching this regex pattern */

$api->get('test/([0-9]+)/([0-9]+)', function ($api){

    $matches = $api->getMatches();
    return $matches;

});

/* Real world example with multiple request methods and external callbacks -> /routes/route.test.php */

$api->get('test/?', 'get_all');
$api->get('test/([0-9]+)', 'get');
$api->post('test/([0-9]+)', 'insert');
$api->put('test/([0-9]+)', 'update');
$api->delete('test/([0-9]+)', 'delete');

/* Search route -> /routes/route.search.php */

$api->get('search/([\w\W]+)', 'search');

/* login example and JWT token -> /routes/route.login.php */

$api->post('login', 'login');

/* Parse the request */
$api->parseRequest();

?>