<?php
// BENCHMARK: vulnerable - path_traversal
$page = $_GET["page"];
include($page);
?>
