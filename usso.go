// Copyright 2013 Canonical Ltd.  This software is licensed under the
// GNU Affero General Public License version 3 (see the file LICENSE).

package usso

import (
	"encoding/json"
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
	BaseURL        string
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	TokenKey       string `json:"token_key"`
	TokenName      string `json:"token_name"`
	TokenSecret    string `json:"token_secret"`
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

func (oauth *SSOData) Sign(req *http.Request) error {
	// Sign the provided request.
	auth := `OAuth realm="API", ` +
		`oauth_consumer_key="` + url.QueryEscape(oauth.ConsumerKey) + `", ` +
		`oauth_token="` + url.QueryEscape(oauth.TokenKey) + `", ` +
		`oauth_signature_method="PLAINTEXT", ` +
		`oauth_signature="` + url.QueryEscape(
		oauth.ConsumerSecret+`&`+oauth.TokenSecret) + `", ` +
		`oauth_timestamp="` + strconv.FormatInt(time.Now().Unix(), 10) + `", ` +
		`oauth_nonce="` + strconv.Itoa(int(rand.Intn(99999999))) + `", ` +
		`oauth_version="1.0"`
	req.Header.Add("Authorization", auth)
	return nil
}
