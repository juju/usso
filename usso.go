// Copyright 2013 Canonical Ltd.  This software is licensed under the
// GNU Affero General Public License version 3 (see the file LICENSE).

package usso

import (
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

func generateNonce() string {
	return strconv.Itoa(rand.Intn(100000000))
}

func generateTimestamp() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

func (oauth *SSOData) Sign(req *http.Request) error {
	// Sign the provided request using the OAuth PLAINTEXT method:
	// http://oauth.net/core/1.0/#anchor22.
	signature := oauth.ConsumerSecret + `&` + oauth.TokenSecret
	authData := map[string]string{
		"realm":                  "API",
		"oauth_consumer_key":     oauth.ConsumerKey,
		"oauth_token":            oauth.TokenKey,
		"oauth_signature_method": "PLAINTEXT",
		"oauth_signature":        signature,
		"oauth_timestamp":        generateTimestamp(),
		"oauth_nonce":            generateNonce(),
		"oauth_version":          "1.0",
	}
	// Build OAuth header.
	authHeader := []string{"OAuth"}
	for key, value := range authData {
		authHeader = append(authHeader, fmt.Sprintf(` %s="%s"`, key, url.QueryEscape(value)))
	}
	req.Header.Add("Authorization", strings.Join(authHeader, ""))
	return nil
}
