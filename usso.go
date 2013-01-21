// Copyright 2013 Canonical Ltd.  This software is licensed under the
// GNU Affero General Public License version 3 (see the file LICENSE).

package usso

import (
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

type Credentials struct {
	// Contains the user credentials used to get access token.
	Email        string `json:"email"`
	Password     string `json:"password"`
	TokenName    string `json:"token_name"`
	SSOServerURL string `json:"-"`
}

type SSOData struct {
	// Contains the 
	BaseURL        string
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	TokenKey       string `json:"token_key"`
	TokenName      string `json:"token_name"`
	TokenSecret    string `json:"token_secret"`
}

func GetToken(credentials *Credentials) (*SSOData, error) {
	// Get a valid access token from credentials.
	json_credentials, err := json.Marshal(credentials)
	if err != nil {
		log.Printf("Error: %s\n", err)
		return nil, err
	}
	response, err := http.Post(
		credentials.SSOServerURL,
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
	nonce := nonce()
	timestamp := timestamp()
	auth := fmt.Sprintf(
		`OAuth realm="API", `+
			`oauth_consumer_key="%s", `+
			`oauth_token="%s", `+
			`oauth_signature_method="PLAINTEXT", `+
			`oauth_signature="%s%%26%s", `+
			`oauth_timestamp="%s", `+
			`oauth_nonce="%s", `+
			`oauth_version="1.0"`,
		url.QueryEscape(oauth.ConsumerKey),
		url.QueryEscape(oauth.TokenKey),
		url.QueryEscape(oauth.ConsumerSecret),
		url.QueryEscape(oauth.TokenSecret),
		url.QueryEscape(timestamp),
		url.QueryEscape(nonce))
	return auth
}

func (oauth *SSOData) Sign(req *http.Request) error {
	// Sign the provided request.
	auth := oauth.GetAuthorizationHeader()
	req.Header.Add("Authorization", auth)
	return nil
}

func (oauth *SSOData) signature(
	http_method, params, signature_method, nonce, timestamp string) (
	string, error) {
	// Depending on the signature method, create the signature from the 
	// consumer secret, the token secret and, if required, the URL.
	// Supported signature methods are PLAINTEXT and HMAC-SHA1.

	switch signature_method {
	case "PLAINTEXT":
		return fmt.Sprintf(
			`oauth_signature="%s%%26%s"`,
			oauth.ConsumerSecret,
			oauth.TokenSecret), nil
	case "HMAC-SHA1":
		base_string := fmt.Sprint(`%s&%s%s`,
			http_method,
			url.QueryEscape(oauth.BaseURL),
			url.QueryEscape(params),
			url.QueryEscape("&oauth_consumer_key="+oauth.ConsumerKey),
			url.QueryEscape("&oauth_nonce="+nonce),
			url.QueryEscape("&oauth_signature_method="+signature_method),
			url.QueryEscape("&oauth_timestamp="+timestamp),
			url.QueryEscape("&oauth_token="+oauth.TokenSecret),
			"&oauth_version=1.0",
			"&size=original")
		hasher := sha1.New()
		hasher.Write([]byte(base_string))
		sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
		return sha, nil
	default:
		return "", nil //FIXME return an appropriate error
	}
	return "", nil
}
