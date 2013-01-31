package usso

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Remove the standard ports from the URL.
func normalizeHost(scheme, hostSpec string) string {
	standardPorts := map[string]string{
		"http":  "80",
		"https": "443",
	}
	hostParts := strings.Split(hostSpec, ":")
	if len(hostParts) == 2 && hostParts[1] == standardPorts[scheme] {
		// There's a port, but it's the default one.  Leave it out.
		return hostParts[0]
	}
	return hostSpec
}

// Normalize the URL according to OAuth specs.
func NormalizeURL(inputUrl string) (string, error) {
	parsedUrl, err := url.Parse(inputUrl)
	if err != nil {
		return "", err
	}

	host := normalizeHost(parsedUrl.Scheme, parsedUrl.Host)
	normalizedUrl := fmt.Sprintf(
		"%v://%v%v", parsedUrl.Scheme, host, parsedUrl.Path)
	return normalizedUrl, nil
}

// Normalize the parameters in the query string according to OAuth specs.
// url.Values.Encode encoded the GET parameters in a consistent order
// we do the encoding ourselves.
func NormalizeParameters(parameters url.Values) (string, error) {
	filteredMap := make(url.Values, len(parameters))
	keys := make([]string, len(parameters))
	i := 0
	for key, _ := range parameters {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "oauth_signature" {
			filteredMap[key] = parameters[key]
		}
	}
	parts := make([]string, 0, len(filteredMap))
	for _, key := range keys {
		prefix := url.QueryEscape(key) + "="
		for _, v := range filteredMap[key] {
			parts = append(parts, prefix+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&"), nil
}
