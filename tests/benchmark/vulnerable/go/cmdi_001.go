// BENCHMARK: vulnerable - cmdi
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func runHandler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("cmd")
	out, err := exec.Command("sh", "-c", userInput).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

func main() {
	http.HandleFunc("/run", runHandler)
	http.ListenAndServe(":8080", nil)
}
