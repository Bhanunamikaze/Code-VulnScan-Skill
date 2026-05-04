<?php
// BENCHMARK: safe - pdo_prepared_statement
$pdo = new PDO("mysql:host=localhost;dbname=mydb", "user", "pass");

$id = $_GET["id"];
// Safe: PDO prepared statement with bindParam prevents SQL injection
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(":id", $id, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $row) {
    echo htmlspecialchars($row["username"]) . "<br>";
}
?>
