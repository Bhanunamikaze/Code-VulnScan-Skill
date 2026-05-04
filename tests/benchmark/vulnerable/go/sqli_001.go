// BENCHMARK: vulnerable - sqli
package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM products WHERE name='%s'", name))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "found rows: %v", rows)
}

func main() {
	http.HandleFunc("/search", searchHandler)
	http.ListenAndServe(":8080", nil)
}
