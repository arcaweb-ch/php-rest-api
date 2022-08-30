<?php

function search($api){

    $keywords = $api->getFirstMatch();

    return "You searched for \"" . $keywords . "\"";

}

?>