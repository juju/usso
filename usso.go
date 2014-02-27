package usso

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type UbuntuSSOServer struct {
	baseUrl              string
	tokenRegistrationUrl string
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

// LoginURL returns the url for Openid login
func (server UbuntuSSOServer) LoginURL() string {
	return server.baseUrl
}

// ProductionUbuntuSSOServer represents the production Ubuntu SSO server
// located at https://login.ubuntu.com.
var ProductionUbuntuSSOServer = UbuntuSSOServer{"https://login.ubuntu.com", "https://one.ubuntu.com/oauth/sso-finished-so-get-tokens/"}

// StagingUbuntuSSOServer represents the staging Ubuntu SSO server located
// at https://login.staging.ubuntu.com. Use it for testing.
var StagingUbuntuSSOServer = UbuntuSSOServer{"https://login.staging.ubuntu.com", "https://one.staging.ubuntu.com/oauth/sso-finished-so-get-tokens/"}

// Giving user credentials and token name, retrieves oauth credentials
// for the users, the oauth credentials can be used later to sign requests.
func (server UbuntuSSOServer) GetToken(email string, password string, tokenName string) (*SSOData, error) {
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
	}
	jsonCredentials, err := json.Marshal(credentials)
	if err != nil {
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
		return nil, fmt.Errorf("Wrong credentials.")
	}
	if response.StatusCode != 200 && response.StatusCode != 201 {
		return nil, fmt.Errorf("SSO Error: %s\n", response.Status)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	ssodata := SSOData{}
	err = json.Unmarshal(body, &ssodata)
	if err != nil {
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
		return "", err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode == 200 {
		return string(body), nil
	} else {
		var jsonMap map[string]interface{}
		err = json.Unmarshal(body, &jsonMap)
		// In theory, this should never happen.
		if err != nil {
			return "", fmt.Errorf("NO_JSON_RESPONSE")
		}
		code, ok := jsonMap["code"]
		if !ok {
			return "", fmt.Errorf("NO_CODE")
		}
		return "", fmt.Errorf("%v", code)
	}
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
		return "", err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode == 200 {
		return string(body), nil
	} else {
		var jsonMap map[string]interface{}
		err = json.Unmarshal(body, &jsonMap)
		// due to bug #1285176, it is possible to get non json code in the response.
		if err != nil {
			return "", fmt.Errorf("INVALID_CREDENTIALS")
		}
		code, ok := jsonMap["code"]
		if !ok {
			return "", fmt.Errorf("NO_CODE")
		}
		return "", fmt.Errorf("%v", code)
	}
}

// Verify the validity of the token, abusing the API to get the token details.
func (server UbuntuSSOServer) IsTokenValid(ssodata *SSOData) (bool, error) {
	details, err := server.GetTokenDetails(ssodata)
	if details != "" && err == nil {
		return true, nil
	} else {
		return false, err
	}
}
