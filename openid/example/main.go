// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENSE file for details.

// Example web application that performs an OpenID login to Ubuntu SSO.
// When making a request to the host it redirects you to Ubuntu SSO to
// log in. If there are any teams specified by the -teams flag,
// membership information for those teams will be requested with the
// login. If any fields are specified by the -optional or -required
// flags, then these values will be requested with the log in.
package main

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/juju/usso"
	"github.com/juju/usso/openid"
)

var (
	optional = flag.String("optional", "", "comma separated list of optional simple registration fields.")
	required = flag.String("required", "", "comma separated list of required simple registration fields.")
	teams    = flag.String("teams", "", "comma separated list of teams to request membership of.")
)

var client = openid.NewClient(usso.ProductionUbuntuSSOServer, nil, nil)

func main() {
	flag.Parse()
	http.Handle("/", http.HandlerFunc(openID))
	err := http.ListenAndServe("localhost:8080", nil)
	fmt.Fprintf(os.Stderr, "%s", err)
}

func openID(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	url := *r.URL
	url.Scheme = "http"
	url.Host = "localhost:8080"
	if r.Form.Get("openid.ns") == "" {
		req := openid.Request{
			ReturnTo:     url.String(),
			Teams:        strings.FieldsFunc(*teams, isComma),
			SRegRequired: strings.FieldsFunc(*required, isComma),
			SRegOptional: strings.FieldsFunc(*optional, isComma),
		}
		url := client.RedirectURL(&req)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
	resp, err := client.Verify(url.String())
	w.Header().Set("ContentType", "text/html")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorTemplate.Execute(w, err)
		return
	}
	loginTemplate.Execute(w, resp)
}

func isComma(c rune) bool {
	return c == ','
}

var errorTemplate = template.Must(template.New("failure").Parse(`<html>
<head><title>Login Error</title></head>
<body>{{.}}</body>
</html>
`))

var loginTemplate = template.Must(template.New("success").Parse(`<html>
<head><title>Login Success</title></head>
<body>
<table>
<tr><th>Claimed ID</th><td>{{.ID}}</td></tr>{{if .Teams}}
<tr><th>Teams</th><td>{{.Teams}}</td></tr>
{{end}}{{range $k, $v := .SimpleRegistration}}
<tr><th>{{$k}}</th><td>{{$v}}</td></tr>
{{end}}</table>
</body>
</html>
`))
