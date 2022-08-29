<?php

function login($api){

    /*
        Request payload validation
    */

    if ($errors = $api->validateParams(array(
        'username' => 'required|email',
        'password' => 'required|string'
    ))){
        $api->outputBadRequest($errors);
    }

    /*
        Todo: check username and password
    */

    $jwt_secret_key = 'my_secret_key';

    $token = $api->generateJWT(array(
        'sub'=>'1234567890',
        'name'=>'John Doe',
        'admin'=>true,
        'exp'=>(time() + 86400)
    ), $jwt_secret_key);

    $refresh_token = $api->generateJWT(array(
        'sub'=>'1234567890',
        'name'=>'John Doe',
        'admin'=>true,
        'exp'=>(time() + 86400+86400)
    ), $jwt_secret_key);

    return array(
        'token' => $token,
        'refresh_token' => $refresh_token
    );

}

?>