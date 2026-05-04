<?php
// BENCHMARK: safe - basename_path_sanitization
$page = $_GET["page"];
// Safe: basename() strips directory components; only filename portion is used
$safe_page = basename($page);
// Additional allowlist check
$allowed = ["home", "about", "contact", "products"];
if (in_array($safe_page, $allowed)) {
    include("pages/" . $safe_page . ".php");
} else {
    include("pages/home.php");
}
?>
