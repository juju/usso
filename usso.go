// Copyright 2013 Canonical Ltd.  This software is licensed under the

package usso

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	// Initialize the random generator.
	rand.Seed(time.Now().UTC().UnixNano())
}

func timestamp() string {
	// Create a timestamp used in authorization header.
	return strconv.Itoa(int(time.Now().Unix()))
}

func nonce() string {
	// Create a nonce used in authorization header.
	return strconv.Itoa(rand.Intn(100000000))
}

type UbuntuSSOServer struct {
	baseUrl string
}

// tokenURL returns the URL where the Ubuntu SSO tokens can be requested.
func (server UbuntuSSOServer) tokenURL() string {
	return server.baseUrl + "/api/v2/tokens"
}

// ProductionUbuntuSSOServer represents the production Ubuntu SSO server
// located at https://login.ubuntu.com.
var ProductionUbuntuSSOServer = UbuntuSSOServer{"https://login.ubuntu.com"}

// StagingUbuntuSSOServer represents the staging Ubuntu SSO server located
// at https://login.staging.ubuntu.com. Use it for testing.
var StagingUbuntuSSOServer = UbuntuSSOServer{"https://login.staging.ubuntu.com"}

type SSOData struct {
	// Contains the oauth data to perform a request.
	HTTPMethod      string     `json:"-"`
	BaseURL         string     `json:"-"`
	Params          url.Values `json:"-"`
	Nonce           string     `json:"-"`
	Timestamp       string     `json:"-"`
	SignatureMethod string     `json:"-"`
	ConsumerKey     string     `json:"consumer_key"`
	ConsumerSecret  string     `json:"consumer_secret"`
	TokenKey        string     `json:"token_key"`
	TokenName       string     `json:"token_name"`
	TokenSecret     string     `json:"token_secret"`
}

func (server UbuntuSSOServer) GetToken(email string, password string, tokenName string) (*SSOData, error) {
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
	}
	json_credentials, err := json.Marshal(credentials)
	if err != nil {
		log.Printf("Error: %s\n", err)
		return nil, err
	}
	response, err := http.Post(
		server.tokenURL(),
		"application/json",
		strings.NewReader(string(json_credentials)))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	ssodata := SSOData{}
	err = json.Unmarshal(body, &ssodata)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &ssodata, nil
}

func (oauth *SSOData) GetAuthorizationHeader() string {
	// Sign the provided request.
	if oauth.Nonce == "" {
		oauth.Nonce = nonce()
	}
	if oauth.Timestamp == "" {
		oauth.Timestamp = timestamp()
	}
	signature := oauth.signature()

	auth := fmt.Sprintf(
		`OAuth realm="API", `+
			`oauth_consumer_key="%s", `+
			`oauth_token="%s", `+
			`oauth_signature_method="%s", `+
			`oauth_signature="%s", `+
			`oauth_timestamp="%s", `+
			`oauth_nonce="%s", `+
			`oauth_version="1.0"`,
		url.QueryEscape(oauth.ConsumerKey),
		url.QueryEscape(oauth.TokenKey),
		oauth.SignatureMethod,
		signature,
		url.QueryEscape(oauth.Timestamp),
		url.QueryEscape(oauth.Nonce))

	return auth
}

func (oauth *SSOData) Sign(req *http.Request) error {
	// Sign the provided request.
	auth := oauth.GetAuthorizationHeader()
	req.Header.Add("Authorization", auth)
	return nil
}

func (oauth *SSOData) signature() string {
	// Depending on the signature method, create the signature from the 
	// consumer secret, the token secret and, if required, the URL.
	// Supported signature methods are PLAINTEXT and HMAC-SHA1.

	switch oauth.SignatureMethod {
	case "PLAINTEXT":
		return fmt.Sprintf(
			`%s%%26%s`,
			oauth.ConsumerSecret,
			oauth.TokenSecret)
	case "HMAC-SHA1":
		base_url, _ := NormalizeURL(oauth.BaseURL)
		params, _ := NormalizeParameters(oauth.Params)
		base_string := fmt.Sprintf(`%s&%s&%s%s%s%s%s%s%s`,
			oauth.HTTPMethod,
			url.QueryEscape(base_url),
			url.QueryEscape(params),
			url.QueryEscape("oauth_consumer_key="+oauth.ConsumerKey),
			url.QueryEscape("&oauth_nonce="+oauth.Nonce),
			url.QueryEscape("&oauth_signature_method="+oauth.SignatureMethod),
			url.QueryEscape("&oauth_timestamp="+oauth.Timestamp),
			url.QueryEscape("&oauth_token="+oauth.TokenKey),
			url.QueryEscape("&oauth_version=1.0"))
		hashfun := hmac.New(sha1.New, []byte(
			oauth.ConsumerSecret+"&"+oauth.TokenSecret))
		hashfun.Write([]byte(base_string))
		rawsignature := hashfun.Sum(nil)
		base64signature := make(
			[]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
		base64.StdEncoding.Encode(base64signature, rawsignature)
		return string(base64signature)
	}
	return ""
}
