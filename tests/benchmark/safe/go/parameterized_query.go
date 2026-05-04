// BENCHMARK: safe - parameterized_query
package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	// Safe: parameterized query with ? placeholder
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)
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
