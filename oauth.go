package usso

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Initialize the random generator.
func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// Create a timestamp used in authorization header.
func timestamp() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

// Create a nonce used in authorization header.
func nonce() string {
	return strconv.Itoa(rand.Intn(100000000))
}

// Contains the oauth data to perform a request.
type SSOData struct {
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

// Depending on the signature method, create the signature from the 
// consumer secret, the token secret and, if required, the URL.
// Supported signature methods are PLAINTEXT and HMAC-SHA1.
func (oauth *SSOData) signature() (string, error) {
	switch oauth.SignatureMethod {
	case "PLAINTEXT":
		return fmt.Sprintf(
			`%s%%26%s`,
			oauth.ConsumerSecret,
			oauth.TokenSecret), nil
	case "HMAC-SHA1":
		base_url, err := NormalizeURL(oauth.BaseURL)
		if err != nil {
			return "", err
		}
		params, err := NormalizeParameters(oauth.Params)
		if err != nil {
			return "", err
		}
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
		return string(base64signature), nil
	default:
		return "", errors.New(
			"usso/oauth: Oauth Signature Method not supported.")
	}
	return "", nil
}

// Sign the provided request.
func (oauth *SSOData) GetAuthorizationHeader() (string, error) {
	if oauth.Nonce == "" {
		oauth.Nonce = nonce()
	}
	if oauth.Timestamp == "" {
		oauth.Timestamp = timestamp()
	}
	signature, err := oauth.signature()
	if err != nil {
		return "", err
	}
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

	return auth, nil
}

// Sign the provided request.
func (oauth *SSOData) SignRequest(req *http.Request) error {
	auth, error := oauth.GetAuthorizationHeader()
	req.Header.Add("Authorization", auth)
	return error
}
