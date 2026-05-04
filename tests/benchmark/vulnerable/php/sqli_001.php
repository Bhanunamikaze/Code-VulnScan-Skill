<?php
// BENCHMARK: vulnerable - sqli
$conn = mysql_connect("localhost", "root", "");
mysql_select_db("mydb", $conn);

$id = $_GET["id"];
$result = mysql_query("SELECT * FROM users WHERE id=" . $id, $conn);
while ($row = mysql_fetch_assoc($result)) {
    echo $row["username"] . "<br>";
}
mysql_close($conn);
?>
