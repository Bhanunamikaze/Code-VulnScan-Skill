// Intentionally vulnerable Go — used for test fixtures ONLY
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"database/sql"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
	// SQLi via fmt.Sprintf
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name)
	db.Query(query)
}

func runHandler(w http.ResponseWriter, r *http.Request) {
	// CMDi via user input
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("bash", "-c", cmd).Output()
	w.Write(out)
}

const dbPassword = "hardcoded-db-pass-xyz"
