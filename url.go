package usso

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Remove the standard ports from the URL.
func normalizeHost(scheme, host_spec string) string {
	standard_ports := map[string]string{
		"http":  "80",
		"https": "443",
	}
	host_parts := strings.Split(host_spec, ":")
	if len(host_parts) == 2 && host_parts[1] == standard_ports[scheme] {
		// There's a port, but it's the default one.  Leave it out.
		return host_parts[0]
	}
	return host_spec
}

// Normalize the URL according to OAuth specs.
func NormalizeURL(input_url string) (string, error) {
	parsed_url, err := url.Parse(input_url)
	if err != nil {
		return "", err
	}

	host := normalizeHost(parsed_url.Scheme, parsed_url.Host)
	normalized_url := fmt.Sprintf(
		"%v://%v%v", parsed_url.Scheme, host, parsed_url.Path)
	return normalized_url, nil
}

// Normalize the parameters in the query string according to OAuth specs.
// url.Values.Encode encoded the GET parameters in a consistent order
// we do the encoding ourselves.
func NormalizeParameters(parameters url.Values) (string, error) {
	filtered_map := make(url.Values, len(parameters))
	keys := make([]string, len(parameters))
	i := 0
	for key, _ := range parameters {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "oauth_signature" {
			filtered_map[key] = parameters[key]
		}
	}
	parts := make([]string, 0, len(filtered_map))
	for _, key := range keys {
		prefix := url.QueryEscape(key) + "="
		for _, v := range filtered_map[key] {
			parts = append(parts, prefix+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&"), nil
}
