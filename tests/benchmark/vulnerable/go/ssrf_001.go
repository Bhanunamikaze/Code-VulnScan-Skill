// BENCHMARK: vulnerable - ssrf
package main

import (
	"fmt"
	"io"
	"net/http"
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, "%s", body)
}

func main() {
	http.HandleFunc("/proxy", proxyHandler)
	http.ListenAndServe(":8080", nil)
}
