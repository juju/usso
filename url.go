package usso

import (
	"fmt"
	"net/url"
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
func NormalizeParameters(parameters url.Values) (string, error) {
	filtered_map := make(url.Values, len(parameters))
	for param, value := range parameters {
		if param != "oauth_signature" {
			filtered_map[param] = value
		}
	}
	return filtered_map.Encode(), nil
}
