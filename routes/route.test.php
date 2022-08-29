<?php

function parse_multiple_params($api){

    $matches = $api->getMatches();

    return array(
        'count' => sizeof($matches),
        'matches' => $matches
    );

}

function get_all(){
    return array(
        array(
            'id' => 1,
            'name' => 'test'
        ),
        array(
            'id' => 2,
            'name' => 'test2'
        ),
    );

}

function get($api){

    $id = $api->getFirstMatch();

    /* Select from DB */

    return array(
        'id' => $id
    );

}

function insert($api){

    $id = $api->getFirstMatch();

    if ($errors = $api->validateParams(array(
        'name' => 'required|string'
    ))){
        $api->outputBadRequest($errors);
    }

    /* Insert DB */

    return 'Inserting test item with id: ' . $id;

}

function update($api){

    $id = $api->getFirstMatch();

    if ($errors = $api->validateParams(array(
        'name' => 'required|string'
    ))){
        $api->outputBadRequest($errors);
    }

    /* Update DB */

    return 'Updating test item with id: ' . $id;

}

function delete($api){

    $id = $api->getFirstMatch();
    
    return 'Deleting test item with id: ' . $id;

}

?>