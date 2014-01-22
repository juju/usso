package usso

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type UbuntuSSOServer struct {
	baseUrl string
}

// tokenURL returns the URL where the Ubuntu SSO tokens can be requested.
func (server UbuntuSSOServer) tokenURL() string {
	return server.baseUrl + "/api/v2/tokens/oauth"
}

// AccountURL returns the URL where the Ubuntu SSO account information can be
// requested.
func (server UbuntuSSOServer) AccountsURL() string {
	return server.baseUrl + "/api/v2/accounts/"
}

// TokenDetailURL returns the URL where the Ubuntu SSO token details can be
// requested.
func (server UbuntuSSOServer) TokenDetailsURL() string {
	return server.baseUrl + "/api/v2/tokens/oauth/"
}

// ProductionUbuntuSSOServer represents the production Ubuntu SSO server
// located at https://login.ubuntu.com.
var ProductionUbuntuSSOServer = UbuntuSSOServer{"https://login.ubuntu.com"}

// StagingUbuntuSSOServer represents the staging Ubuntu SSO server located
// at https://login.staging.ubuntu.com. Use it for testing.
var StagingUbuntuSSOServer = UbuntuSSOServer{"https://login.staging.ubuntu.com"}

// Giving user credentials and token name, retrieves oauth credentials
// for the users, the oauth credentials can be used later to sign requests.
func (server UbuntuSSOServer) GetToken(
	email string, password string, tokenName string) (*SSOData, error) {
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
	}
	jsonCredentials, err := json.Marshal(credentials)
	if err != nil {
		log.Printf("Error: %s\n", err)
		return nil, err
	}
	response, err := http.Post(
		server.tokenURL(),
		"application/json",
		strings.NewReader(string(jsonCredentials)))
	if err != nil {
		return nil, err
	}
	if response.StatusCode == 404 {
		return nil, errors.New("Wrong credentials.")
	}
	if response.StatusCode != 200 && response.StatusCode != 201 {
		return nil, fmt.Errorf("SSO Error: %s\n", response.Status)
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
	ssodata.Realm = "API"
	return &ssodata, nil
}

// Returns all the Ubuntu SSO information related to this account.
func (server UbuntuSSOServer) GetAccounts(ssodata *SSOData) (string, error) {
	rp := RequestParameters{
		BaseURL:         server.AccountsURL() + ssodata.ConsumerKey,
		HTTPMethod:      "GET",
		SignatureMethod: HMACSHA1{}}

	request, err := http.NewRequest(rp.HTTPMethod, rp.BaseURL, nil)
	if err != nil {
		return "", err
	}
	err = SignRequest(ssodata, &rp, request)
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

// Given oauth credentials and a request, return it signed.
func SignRequest(
	ssodata *SSOData, rp *RequestParameters, request *http.Request) error {
	return ssodata.SignRequest(rp, request)
}

// Given oauth credentials return a valid http authorization header.
func GetAuthorizationHeader(
	ssodata *SSOData, rp *RequestParameters) (string, error) {
	header, err := ssodata.GetAuthorizationHeader(rp)
	return header, err
}

// Returns all the Ubuntu SSO information related to this token.
func (server UbuntuSSOServer) GetTokenDetails(ssodata *SSOData) (string, error) {
	rp := RequestParameters{
		BaseURL:         server.TokenDetailsURL() + ssodata.TokenKey,
		HTTPMethod:      "GET",
		SignatureMethod: HMACSHA1{}}

	request, err := http.NewRequest(rp.HTTPMethod, rp.BaseURL, nil)
	if err != nil {
		return "", err
	}
	err = SignRequest(ssodata, &rp, request)
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

// Register the toke to the U1 File Sync Service.
func (server UbuntuSSOServer) RegisterTokenToU1FileSync(ssodata *SSOData) (err error) {
	rp := RequestParameters{
		BaseURL:         "https://one.ubuntu.com/oauth/sso-finished-so-get-tokens/",
		HTTPMethod:      "GET",
		SignatureMethod: HMACSHA1{}}

	request, err := http.NewRequest(rp.HTTPMethod, rp.BaseURL, nil)
	if err != nil {
		return err
	}
	ssodata.Realm = ""
	err = SignRequest(ssodata, &rp, request)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println(err)
		}
		var b bytes.Buffer
		b.Write(body)
		errors.New(fmt.Sprint(b.String()))
	}
	return nil
}
