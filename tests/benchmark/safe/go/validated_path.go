// BENCHMARK: safe - validated_path_traversal_prevention
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const safeDir = "/var/app/files"

func fileHandler(w http.ResponseWriter, r *http.Request) {
	rawPath := r.URL.Query().Get("path")
	// Safe: filepath.Clean + HasPrefix ensures path stays within safeDir
	cleanPath := filepath.Clean(filepath.Join(safeDir, rawPath))
	if !strings.HasPrefix(cleanPath, safeDir+string(os.PathSeparator)) {
		http.Error(w, "forbidden", 403)
		return
	}
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(content)
}

func main() {
	http.HandleFunc("/file", fileHandler)
	http.ListenAndServe(":8080", nil)
}
