// BENCHMARK: safe - html_template_auto_escaping
package main

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html>
<body><p>Hello, {{.Name}}!</p></body>
</html>
`))

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Safe: html/template auto-escapes all values, preventing XSS
	tmpl.Execute(w, map[string]string{"Name": name})
}

func main() {
	http.HandleFunc("/greet", greetHandler)
	http.ListenAndServe(":8080", nil)
}
