package usso

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
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

// AccountURL returns the URL where the Ubuntu SSO account information can be 
// requested.
func (server UbuntuSSOServer) AccountsURL() string {
	return server.baseUrl + "/api/v2/accounts/"
}

// ProductionUbuntuSSOServer represents the production Ubuntu SSO server
// located at https://login.ubuntu.com.
var ProductionUbuntuSSOServer = UbuntuSSOServer{"https://login.ubuntu.com"}

// StagingUbuntuSSOServer represents the staging Ubuntu SSO server located
// at https://login.staging.ubuntu.com. Use it for testing.
var StagingUbuntuSSOServer = UbuntuSSOServer{"https://login.staging.ubuntu.com"}

func (server UbuntuSSOServer) GetToken(
	// Giving user credentials and token name, retrieves oauth credentials
	// for the users, the oauth credentials can be used later to sign requests.
	email string, password string, tokenName string) (*SSOData, error) {
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

func (server UbuntuSSOServer) GetAccounts(ssodata *SSOData) (string, error) {
	// Returns all the Ubuntu SSO information related to this account.
	ssodata.BaseURL = server.AccountsURL() + ssodata.ConsumerKey
	ssodata.HTTPMethod = "GET"
	ssodata.SignatureMethod = "HMAC-SHA1"
	request, err := http.NewRequest(ssodata.HTTPMethod, ssodata.BaseURL, nil)
	if err != nil {
		return "", err
	}
	err = SignRequest(ssodata, request)
	if err != nil {
		return "", err
	}
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
	}
	var b bytes.Buffer
	b.Write(body)
	return fmt.Sprint(b.String()), nil
}

func SignRequest(ssodata *SSOData, request *http.Request) error {
	// Given oauth credentials and a request, return it signed.
	return ssodata.SignRequest(request)
}

func GetAuthorizationHeader(ssodata *SSOData) (string, error) {
	// Given oauth credentials return a valid http authorization header.
	header, err := ssodata.GetAuthorizationHeader()
	return header, err
}
