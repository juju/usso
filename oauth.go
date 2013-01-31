package usso

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
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
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	TokenKey       string `json:"token_key"`
	TokenName      string `json:"token_name"`
	TokenSecret    string `json:"token_secret"`
}

type RequestParameters struct {
	HTTPMethod      string
	BaseURL         string
	Params          url.Values
	Nonce           string
	Timestamp       string
	SignatureMethod SignatureMethod
}

type SignatureMethod interface {
	Name() string
	Signature(
		ssodata *SSOData, rp *RequestParameters) (string, error)
}

type PLAINTEXT struct{}

func (PLAINTEXT) Name() string { return "PLAINTEXT" }
func (PLAINTEXT) Signature(
	ssodata *SSOData, rp *RequestParameters) (string, error) {
	return fmt.Sprintf(
		`%s&%s`,
		ssodata.ConsumerSecret,
		ssodata.TokenSecret), nil
}

type HMACSHA1 struct{}

func (HMACSHA1) Name() string { return "HMAC-SHA1" }
func (HMACSHA1) Signature(
	ssodata *SSOData, rp *RequestParameters) (string, error) {
	baseUrl, err := NormalizeURL(rp.BaseURL)
	if err != nil {
		return "", err
	}
	params, err := NormalizeParameters(rp.Params)
	if err != nil {
		return "", err
	}
	baseString := fmt.Sprintf(`%s&%s&%s%s%s%s%s%s%s`,
		rp.HTTPMethod,
		url.QueryEscape(baseUrl),
		url.QueryEscape(params),
		url.QueryEscape("oauth_consumer_key="+ssodata.ConsumerKey),
		url.QueryEscape("&oauth_nonce="+rp.Nonce),
		url.QueryEscape(
			"&oauth_signature_method="+string(rp.SignatureMethod.Name())),
		url.QueryEscape("&oauth_timestamp="+rp.Timestamp),
		url.QueryEscape("&oauth_token="+ssodata.TokenKey),
		url.QueryEscape("&oauth_version=1.0"))
	hashfun := hmac.New(sha1.New, []byte(
		ssodata.ConsumerSecret+"&"+ssodata.TokenSecret))
	hashfun.Write([]byte(baseString))
	rawsignature := hashfun.Sum(nil)
	base64signature := make(
		[]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)
	return string(base64signature), nil
}

// Sign the provided request.
func (ssodata *SSOData) GetAuthorizationHeader(
	rp *RequestParameters) (string, error) {
	if rp.Nonce == "" {
		rp.Nonce = nonce()
	}
	if rp.Timestamp == "" {
		rp.Timestamp = timestamp()
	}
	signature, err := rp.SignatureMethod.Signature(ssodata, rp)
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
		url.QueryEscape(ssodata.ConsumerKey),
		url.QueryEscape(ssodata.TokenKey),
		rp.SignatureMethod.Name(),
		signature,
		url.QueryEscape(rp.Timestamp),
		url.QueryEscape(rp.Nonce))

	return auth, nil
}

// Sign the provided request.
func (ssodata *SSOData) SignRequest(
	rp *RequestParameters, req *http.Request) error {
	auth, error := ssodata.GetAuthorizationHeader(rp)
	req.Header.Add("Authorization", auth)
	return error
}
