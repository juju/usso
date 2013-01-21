package usso

import (
	"fmt"
	"net/url"
	"strings"
)


func NormalizeMethod(input_url string) (string, error) {
	parsed_url, err := url.Parse(input_url)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(parsed_url.Scheme), nil
}


func NormalizeURL(input_url string) (string, error) {
/*
	standard_ports := map[string]int{
		"http": 80,
		"https": 443,
	}
*/
	parsed_url, err := url.Parse(input_url)
	if err != nil {
		return "", err
	}

/*
	if parsed_url.Port == standard_ports[parsed_url.Scheme] {
		port_spec := ""
	} else {
		port_spec := fmt.Sprintf(":%v", parsed_url.Port)
	}
*/ port_spec := ""
	normalized_url := fmt.Sprintf("%v://%v%v%v", parsed_url.Scheme, parsed_url.Host, port_spec, parsed_url.Path)
	return normalized_url, nil
}


func NormalizeParameters(parameters map[string]string) (string, error) {
	return "", nil
}
