<?php
// BENCHMARK: safe - htmlspecialchars_output_encoding
$name = $_GET["name"];
// Safe: htmlspecialchars encodes HTML special chars, preventing XSS
echo "Hello, " . htmlspecialchars($name, ENT_QUOTES, "UTF-8") . "!";
?>
