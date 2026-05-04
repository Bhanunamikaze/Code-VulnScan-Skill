<?php
// BENCHMARK: vulnerable - cmdi
$cmd = $_GET["cmd"];
echo system($cmd);
?>
