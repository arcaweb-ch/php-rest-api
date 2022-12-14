<?php

/**
 * PHP REST API Class
 *
 * A simple PHP REST API Class
 *
 * PHP version 7.0
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
 * @copyright   2022 Arcaweb
 * @license     https://www.gnu.org/licenses/gpl-3.0.txt
 * @version     SVN: 1.0.0
 * @link        https://github.com/arcaweb-ch/php-rest-api
 */

class RestApi{

    private $config = array();

    private $routes;
    private $requestMethod;
    private $requestURI;
    private $processedURI;
    private $processedCallback;
    private $requestBody;
    private $requestMatches;
    private $processedRoute;
    private $endpoint;
    private $fatalError = false;

    // constructor
    function __construct($config = array()) {
       
        $this->config = array_merge(array(
            'log_errors' => false,
            'return_server_errors' => false,
            'return_server_error_level' => LOG_NOTICE, // https://www.php.net/manual/en/function.syslog.php
            'log_server_error_level' => LOG_NOTICE, // https://www.php.net/manual/en/function.syslog.php
            'error_log_path' => '',
            'auto_include_route_file' => true
        ), $config);

        $this->routes = array();
        $this->routes['get'] = array();
        $this->routes['post'] = array();
        $this->routes['put'] = array();
        $this->routes['delete'] = array();
        
        $this->initErrorHandler();
       
    }
    
    private function base64url_encode($str) {

        /**
         * Helper function to encode data
         */

        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    private function initErrorHandler(){

        /**
         * Error handling initialization
         */

        error_reporting(E_ALL);
        ini_set('display_errors', 0);

        set_error_handler(array($this, 'errorHandler'));
        register_shutdown_function(array($this, 'shutdownHandler'));

    }

    public function shutdownHandler(){

        /**
         * Shutdown handler
         */

        $error = error_get_last();

        if($error !== NULL){

            $this->errorHandler($error['type'], $error['message'], $error['file'], $error['line']);

        }

    }

    private function mapErrorCode($code) {

        /**
         * Map PHP error codes
         */

        $type = $level = null;

        switch($code){
            case E_ERROR: // 1 //
                $type = 'E_ERROR';
                $level = LOG_ERR; // (4)
            case E_WARNING: // 2 //
                $type = 'E_WARNING';
                $level = LOG_WARNING; // (5)
            case E_PARSE: // 4 //
                $type = 'E_PARSE ERROR';
                $level = LOG_ERR;
            case E_NOTICE: // 8 //
                $type = 'E_NOTICE';
                $level = LOG_NOTICE; // (6)
            case E_CORE_ERROR: // 16 //
                $type = 'E_CORE_ERROR';
                $level = LOG_ERR;
            case E_CORE_WARNING: // 32 //
                $type = 'E_CORE_WARNING';
                $level = LOG_WARNING;
            case E_COMPILE_ERROR: // 64 //
                $type = 'E_COMPILE_ERROR';
                $level = LOG_ERR;
            case E_COMPILE_WARNING: // 128 //
                $type = 'E_COMPILE_WARNING';
                $level = LOG_WARNING;
            case E_USER_ERROR: // 256 //
                $type = 'E_USER_ERROR';
                $level = LOG_ERR;
            case E_USER_WARNING: // 512 //
                $type = 'E_USER_WARNING';
                $level = LOG_WARNING;
            case E_USER_NOTICE: // 1024 //
                $type = 'E_USER_NOTICE';
                $level = LOG_NOTICE;
            case E_STRICT: // 2048 //
                $type = 'E_STRICT NOTICE';
                $level = LOG_NOTICE;
            case E_RECOVERABLE_ERROR: // 4096 //
                $type = 'E_RECOVERABLE_ERROR WARNING';
                $level = LOG_WARNING;
            case E_DEPRECATED: // 8192 //
                $type = 'E_DEPRECATED NOTICE';
                $level = LOG_NOTICE;
            case E_USER_DEPRECATED: // 16384 //
                $type = 'E_USER_DEPRECATED NOTICE';
                $level = LOG_NOTICE;
        }
        return array($type, $level);
    }

    private function errorHandler($code, $description, $file = null, $line = null, $context = null) {
        
        /**
         * Error handling
         */

        if (!(error_reporting() & $code)) {
            return false;
        }
      
        list($type, $level) = $this->mapErrorCode($code);
    
        $data = array(
            'type' => $type.' ('.$code.')',
            'description' => $description,
            'file' => $file,
            'line' => $line,
        );

        // log error
    
        if ($this->config['log_errors']){
            if ($level <= $this->config['log_server_error_level']){
                $this->fileLog($data);
            }
        }

        // return error

        if ($this->config['return_server_errors'] && $level <= $this->config['return_server_error_level']) {
            $this->outputServerError($data);
        } else {
            $this->outputServerError();
        }
    
    }

    public function fileLog($logData) {

        /**
         * Log errors to file
         */
    
        if (empty($this->config['error_log_path'])){
            return;
        }

        $fh = fopen($this->config['error_log_path'], 'a+');
        
        if (is_array($logData)) {
            $logData = print_r($logData, 1);
        }
    
        fwrite($fh, $logData);
        fclose($fh);
    
    }

    public function outputData($data){

        /**
         * Output data
         */

        header('Content-Type: application/json');

        echo json_encode($data);

        die();
    }

    public function outputError($error_code, $error_message = ''){

        /**
         * Output errors
         */

        $error_codes = array(
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            500 => 'Internal Server Error',
        );

        if (!in_array($error_code, array_keys($error_codes))){
            $error_code = 500;
        }

        if ($error_code != 500 && $error = error_get_last()) {

            // If a fatal error was already sent, don't output anything else
           
            list($type, $level) = $this->mapErrorCode($error['type']);
            
            if ($this->config['return_server_errors'] && $level <= $this->config['return_server_error_level']) {
                return;
            }
        }

        header($_SERVER['SERVER_PROTOCOL'] . ' ' . $error_code . ' ' . $error_codes[$error_code], true, $error_code);

        if (!empty($error_message)){
            
            $this->outputData(array(
                'code' => $error_code,
                'error' => !empty($error_message) ? $error_message : $error_codes[$error_code],
            ));
        }

        die();

    }

    public function outputBadRequest($error_message = ''){

        /**
         * Output bad request
         */

        $this->outputError(400, $error_message);

    }

    public function outputServerError($error_message = ''){

        /**
         * Output server error
         */

        $this->outputError(500, $error_message);

    }

    public function outputNotFound(){

        /**
         * Output not found
         */

        $this->outputError(404, 'Not Found');

    }

    public function get($url, $callback) {

        /**
         * Add GET route
         */

        $this->routes['get'][$url] = $callback;

    }

    public function post($url, $callback) {

        /**
         * Add POST route
         */

        $this->routes['post'][$url] = $callback;

    }

    public function put($url, $callback) {

        /**
         * Add PUT route
         */

        $this->routes['put'][$url] = $callback;

    }

    public function delete($url, $callback) {

        /**
         * Add DELETE route
         */

        $this->routes['delete'][$url] = $callback;

    }

    public function getRoutes() {

        /**
         * Get all routes
         */

        return $this->routes;

    }

    public function getRequestBodyData() {

        /**
         * Get request body data
         */

        if (!empty($this->requestBody)){
            
            $requestData = json_decode($this->requestBody, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->outputBadRequest('JSON decode error: ' . json_last_error_msg());
            }

        } else {
            $requestData = array();
        }

        return $requestData;
    }

    public function getParam($param) {

        /**
         * Get request body param
         */

        $data = $this->getRequestBodyData();

        if (isset($data[$param])){
            return $data[$param];
        } else {
            return null;
        }

    }

    public function getMatches() {

        /**
         * Return all route matches
         */

        array_shift($this->requestMatches);

        return $this->requestMatches;

    }

    public function getFirstMatch() {

        /**
         * Return first route match
         */

        $matches = $this->getMatches();

        if (count($matches) > 0){
            return $matches[0];
        } else {
            $this->outputServerError('getFirstMatch: No match found');
        }

    }

    public function autoIncludeRouteFile($bool = true) {

        /**
         * Auto include route file
         */

        $this->config['auto_include_route_file'] = $bool;

    }

    public function validateParams($validator) {

        /**
         * Validate request parameters
         */

        $errors = array();

        $data = $this->getRequestBodyData();
        
        foreach ($validator as $param => $value) {
            
            if (!isset($data[$param]) && strpos($value, 'required') !== false) {
                array_push($errors, $param . ' is required');
                continue;
            }

            if (isset($data[$param])) {

                if (strpos($value, 'int') !== false) {
                    if (!is_int($data[$param])) {
                        array_push($errors, $param . ' must be an integer');
                    }
                }

                if (strpos($value, 'string') !== false) {
                    if (!is_string($data[$param])) {
                        array_push($errors, $param . ' must be a string');
                    }
                }

                if (strpos($value, 'array') !== false) {
                    if (!is_array($data[$param])) {
                        array_push($errors, $param . ' must be an array');
                    }
                }

                if (strpos($value, 'bool') !== false) {
                    if (!is_bool($data[$param])) {
                        array_push($errors, $param . ' must be a boolean');
                    }
                }

                if (strpos($value, 'email') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_EMAIL)) {
                        array_push($errors, $param . ' must be a valid email');
                    }
                }

                if (strpos($value, 'url') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_URL)) {
                        array_push($errors, $param . ' must be a valid url');
                    }
                }

                if (strpos($value, 'ip') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_IP)) {
                        array_push($errors, $param . ' must be a valid ip');
                    }
                }

                if (strpos($value, 'datetime') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => '/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/')))) {
                        array_push($errors, $param . ' must be a valid datetime');
                    }
                }

                if (strpos($value, 'date') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => '/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/')))) {
                        array_push($errors, $param . ' must be a valid date');
                    }
                }

                if (strpos($value, 'time') !== false) {
                    if (!filter_var($data[$param], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => '/^[0-9]{2}:[0-9]{2}:[0-9]{2}$/')))) {
                        array_push($errors, $param . ' must be a valid time');
                    }
                }

            }

        }

        return $errors;

    }

    public function generateJWT($payload, $jwt_secret_key) {

        /**
         * Generate JWT token
         */

        $header = $this->base64url_encode(json_encode(array('alg' => 'HS256', 'typ' => 'JWT')));
        $payload = $this->base64url_encode(json_encode($payload));
        $signature = $this->base64url_encode(hash_hmac('sha256', $header . '.' . $payload, $jwt_secret_key, true));
        
        $jwt = $header . '.' . $payload . '.' . $signature;

        return $jwt;

    }

    public function validateJWT($jwt) {

        /**
         * Validate JWT token
         */

        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        $base64_url_header = $this->base64url_encode($header);
        $base64_url_payload = $this->base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $jwt_secret_key, true);
        $base64_url_signature = $this->base64url_encode($signature);

        $is_signature_valid = ($base64_url_signature === $signature_provided);
        
        if ($is_token_expired || !$is_signature_valid) {
            return FALSE;
        } else {
            return TRUE;
        }
    }

    public function parseRequest() {

        /**
         * Parse request
         */
        
        $this->requestMethod = strtolower($_SERVER['REQUEST_METHOD']);

        if (!isset($_GET['u'])) {
            $this->outputBadRequest('mod_rewrite rule not configured');
        }
        
        $this->requestURI = trim($_GET['u'], '/');

        /* 
            Enumerate routes
        */

        foreach($this->routes[$this->requestMethod] as $uri => $callback) {
            
            if (preg_match('/^' . str_replace('/','\/',$uri) . '$/', $this->requestURI, $matches)) {
                
                $this->processedRoute = $this->routes[$this->requestMethod][$uri];
                $this->requestMatches = $matches;
                break;
            }
        }
        
        /* 
            Check if route exists
        */
        
        if (empty($this->processedRoute)) {
            $this->outputNotFound('Requested route was not found');
        }

        /*
            Auto include route file if exists
        */

        $parts = explode('/', $this->requestURI);

        if (sizeof($parts) > 0) {
            $this->endpoint = $parts[0];

            if ($this->config['auto_include_route_file']){
                if (file_exists(dirname($_SERVER['SCRIPT_FILENAME']).'/routes/route.' . $this->endpoint . '.php')){
                    require_once 'routes/route.' . $this->endpoint . '.php';
                }
            }

        } else {

            $this->endpoint = '';

        }


        /*
            Callback processor
        */

        if (!is_callable($this->processedRoute)) {
            if (!function_exists($this->processedRoute)) {
                $this->outputServerError('Callback not defined');
            }
        }

        $this->requestBody = file_get_contents('php://input');
        $this->response = call_user_func($this->processedRoute, $this);
        
        if ($error = error_get_last()) {

            // If an error was sent, don't output anything
           
            list($type, $level) = $this->mapErrorCode($error['type']);
            
            if ($this->config['return_server_errors'] && $level <= $this->config['return_server_error_level']) {
                return;
            }
        }

        $this->outputData($this->response);

    }

}

?>