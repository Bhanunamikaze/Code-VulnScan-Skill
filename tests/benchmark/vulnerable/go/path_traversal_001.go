// BENCHMARK: vulnerable - path_traversal
package main

import (
	"fmt"
	"net/http"
	"os"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("path")
	f, err := os.Open("/var/data/" + filename)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	content := make([]byte, 4096)
	n, _ := f.Read(content)
	fmt.Fprintf(w, "%s", content[:n])
}

func main() {
	http.HandleFunc("/file", fileHandler)
	http.ListenAndServe(":8080", nil)
}
