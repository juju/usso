package usso

import (
	"net/url"
	"strings"
)


func NormalizeMethod(input_url string) (string, error) {
	parsed_url, err := url.Parse(input_url)
	if err != nil {
		return "ERROR", err
	}
	return strings.ToUpper(parsed_url.Scheme), nil
}


func NormalizeURL(url string) (string, error) {
	return url, nil
}


func NormalizeParameters(parameters map[string]string) (string, error) {
	return "", nil
}
