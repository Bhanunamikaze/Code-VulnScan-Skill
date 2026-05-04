<?php
// BENCHMARK: vulnerable - xss
$name = $_GET["name"];
echo "Hello, " . $name . "!";
?>
