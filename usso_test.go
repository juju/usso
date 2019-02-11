// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENSE file for details.

package usso

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

const (
	tokenName      = "foo"
	tokenKey       = "abcs"
	tokenSecret    = "mTBgLxtTRUdfqewqgrqsvxlijbMWkPBajgKcoZCrDwv"
	realm          = "API"
	consumerKey    = "rfyzhdQ"
	consumerSecret = "rwDkQkkdfdfdeAslkmmxAOjOAT"
	email          = "foo@bar.com"
	password       = "foobarpwd"
	otp            = "000000"
)

// TestProductionUbuntuSSOServerURLs tests the URLs of the production server.
func TestProductionUbuntuSSOServerURLs(t *testing.T) {
	c := qt.New(t)

	tokenURL := ProductionUbuntuSSOServer.tokenURL()
	c.Assert(tokenURL, qt.Equals, "https://login.ubuntu.com/api/v2/tokens/oauth")
}

// TestStagingUbuntuSSOServerURLs tests the URLs of the staging server.
func TestStagingUbuntuSSOServerURLs(t *testing.T) {
	c := qt.New(t)

	tokenURL := StagingUbuntuSSOServer.tokenURL()
	c.Assert(tokenURL, qt.Equals, "https://login.staging.ubuntu.com/api/v2/tokens/oauth")
}

type TestServer struct {
	*httptest.Server
	requestContent *string
}

// newTestServer http server to mock U1 SSO server.
func newTestServer(response, tokenDetails string, code int) *TestServer {
	var requestContent string
	handler := func(w http.ResponseWriter, r *http.Request) {
		res, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		if strings.Contains(string(res), "WRONG") {
			http.Error(w, "404 page not found", http.StatusNotFound)
		}
		if r.URL.String() == "/api/v2/tokens/oauth" {
			requestContent = string(res)
			fmt.Fprint(w, response)
			return
		}
		if r.URL.String() == "/api/v2/tokens/oauth/abcs" {
			fmt.Fprint(w, tokenDetails)
			return
		} else {
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	return &TestServer{server, &requestContent}
}

func TestGetTokenReturnsTokens(t *testing.T) {
	c := qt.New(t)

	// Simulate a valid Ubuntu SSO Server response.
	serverResponseData := map[string]string{
		"date_updated":    "2013-01-16 14:03:36",
		"date_created":    "2013-01-16 14:03:36",
		"href":            "/api/v2/tokens/" + tokenKey,
		"token_name":      tokenName,
		"token_key":       tokenKey,
		"token_secret":    tokenSecret,
		"consumer_key":    consumerKey,
		"consumer_secret": consumerSecret,
	}
	jsonServerResponseData, err := json.Marshal(serverResponseData)
	if err != nil {
		panic(err)
	}
	server := newTestServer(string(jsonServerResponseData), "{}", 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()

	// The returned information is correct.
	ssodata, err := testSSOServer.GetToken(email, password, tokenName)
	c.Assert(err, qt.Equals, nil)
	expectedSSOData := &SSOData{ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, Realm: realm, TokenKey: tokenKey,
		TokenSecret: tokenSecret, TokenName: tokenName}
	c.Assert(ssodata, qt.DeepEquals, expectedSSOData)
	// The request that the fake Ubuntu SSO Server has the credentials.
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
	}
	expectedRequestContent, err := json.Marshal(credentials)
	if err != nil {
		panic(err)
	}
	c.Assert(*server.requestContent, qt.Equals, string(expectedRequestContent))
}

// GetToken should return empty credentials and an error, if wrong account is provided.
func TestGetTokenFails(t *testing.T) {
	c := qt.New(t)

	server := newTestServer("{}", "{}", 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()
	ssodata, err := testSSOServer.GetToken(email, "WRONG", tokenName)
	c.Assert(err, qt.ErrorMatches, `404 page not found`+"\n"+`\{\}`)
	c.Assert(ssodata, qt.IsNil)
}

func TestGetTokenDetails(t *testing.T) {
	c := qt.New(t)

	// Simulate a valid Ubuntu SSO Server response.
	serverResponseData := map[string]string{
		"date_updated": "2013-01-16 14:03:36",
		"date_created": "2013-01-16 14:03:36",
		"href":         "/api/v2/tokens/" + tokenKey,
		"token_name":   tokenName,
		"token_key":    tokenKey,
		"consumer_key": consumerKey,
	}
	jsonServerResponseData, err := json.Marshal(serverResponseData)
	if err != nil {
		panic(err)
	}
	tokenDetails := map[string]string{
		"token_name":   tokenName,
		"date_updated": "2014-01-22T13:35:49.867",
		"token_key":    tokenKey,
		"href":         "/api/v2/tokens/oauth/JckChNpbXxPRmPkElLglSnqnjsnGseWJmNqTJCWfUtNBSsGtoG",
		"date_created": "2014-01-17T20:03:24.993",
		"consumer_key": consumerKey,
	}
	jsonTokenDetails, err := json.Marshal(tokenDetails)
	if err != nil {
		panic(err)
	}
	server := newTestServer(string(jsonServerResponseData), string(jsonTokenDetails), 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()
	ssodata, err := testSSOServer.GetToken(email, password, tokenName)
	// The returned information is correct.
	token_details, err := testSSOServer.GetTokenDetails(ssodata)
	c.Assert(err, qt.IsNil)
	//The request that the fake Ubuntu SSO Server has the token details.
	c.Assert(token_details, qt.Equals, string(jsonTokenDetails))
}

func TestGetTokenWithOTP(t *testing.T) {
	c := qt.New(t)

	// Simulate a valid Ubuntu SSO Server response.
	serverResponseData := map[string]string{
		"date_updated":    "2013-01-16 14:03:36",
		"date_created":    "2013-01-16 14:03:36",
		"href":            "/api/v2/tokens/" + tokenKey,
		"token_name":      tokenName,
		"token_key":       tokenKey,
		"token_secret":    tokenSecret,
		"consumer_key":    consumerKey,
		"consumer_secret": consumerSecret,
	}
	jsonServerResponseData, err := json.Marshal(serverResponseData)
	if err != nil {
		panic(err)
	}
	server := newTestServer(string(jsonServerResponseData), "{}", 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()

	// The returned information is correct.
	ssodata, err := testSSOServer.GetTokenWithOTP(email, password, otp, tokenName)
	c.Assert(err, qt.IsNil)
	expectedSSOData := &SSOData{ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, Realm: realm, TokenKey: tokenKey,
		TokenSecret: tokenSecret, TokenName: tokenName}
	c.Assert(ssodata, qt.DeepEquals, expectedSSOData)
	// The request that the fake Ubuntu SSO Server has the credentials.
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
		"otp":        otp,
	}
	expectedRequestContent, err := json.Marshal(credentials)
	c.Assert(err, qt.IsNil)
	c.Assert(*server.requestContent, qt.Equals, string(expectedRequestContent))
}

func TestTokenValidity(t *testing.T) {
	c := qt.New(t)

	// Simulate a valid Ubuntu SSO Server response.
	serverResponseData := map[string]string{
		"date_updated": "2013-01-16 14:03:36",
		"date_created": "2013-01-16 14:03:36",
		"href":         "/api/v2/tokens/" + tokenKey,
		"token_name":   tokenName,
		"token_key":    tokenKey,
		"consumer_key": consumerKey,
	}
	jsonServerResponseData, err := json.Marshal(serverResponseData)
	if err != nil {
		panic(err)
	}
	tokenDetails := map[string]string{
		"token_name":   tokenName,
		"date_updated": "2014-01-22T13:35:49.867",
		"token_key":    tokenKey,
		"href":         "/api/v2/tokens/oauth/JckChNpbXxPRmPkElLglSnqnjsnGseWJmNqTJCWfUtNBSsGtoG",
		"date_created": "2014-01-17T20:03:24.993",
		"consumer_key": consumerKey,
	}
	jsonTokenDetails, err := json.Marshal(tokenDetails)
	if err != nil {
		panic(err)
	}
	server := newTestServer(string(jsonServerResponseData), string(jsonTokenDetails), 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()
	ssodata, err := testSSOServer.GetToken(email, password, tokenName)
	// The returned information is correct.
	token_details, err := testSSOServer.GetTokenDetails(ssodata)
	c.Assert(err, qt.IsNil)
	//The request that the fake Ubuntu SSO Server has the token details.
	c.Assert(token_details, qt.Equals, string(jsonTokenDetails))
	validity, err := testSSOServer.IsTokenValid(ssodata)
	c.Assert(validity, qt.Equals, true)
}

// Check invalid token
func TestInvalidToken(t *testing.T) {
	c := qt.New(t)

	server := newTestServer("{}", "{}", 200)
	var testSSOServer = &UbuntuSSOServer{server.URL, ""}
	defer server.Close()
	ssodata := SSOData{"WRONG", "", "", "", "", ""}
	validity, err := testSSOServer.IsTokenValid(&ssodata)
	c.Assert(err, qt.ErrorMatches, `INVALID_CREDENTIALS`)
	c.Assert(validity, qt.Equals, false)
}

var getErrorTests = []struct {
	about       string
	status      string
	body        io.Reader
	expectCode  string
	expectError string
}{{
	about:       "valid error",
	body:        strings.NewReader(`{"message": "test error"}`),
	expectError: `test error`,
}, {
	about:       "valid error with code",
	body:        strings.NewReader(`{"message": "test error", "code": "ERROR"}`),
	expectCode:  "ERROR",
	expectError: `test error`,
}, {
	about:       "valid error with extra",
	body:        strings.NewReader(`{"message": "test error", "extra": {"ext": "thing"}}`),
	expectError: `test error \(ext: thing\)`,
}, {
	about:       "bad json",
	status:      "500 Internal Server Error",
	body:        strings.NewReader(`{"message": "test error"`),
	expectCode:  "500 Internal Server Error",
	expectError: `{"message": "test error"`,
}, {
	about:       "bad reader",
	status:      "500 Internal Server Error",
	body:        errorReader{fmt.Errorf("test read error")},
	expectCode:  "500 Internal Server Error",
	expectError: `500 Internal Server Error`,
}}

func TestGetError(t *testing.T) {
	c := qt.New(t)

	for i, test := range getErrorTests {
		c.Logf("%d. %s", i, test.about)
		resp := &http.Response{
			Status: test.status,
			Body:   ioutil.NopCloser(test.body),
		}
		err := getError(resp)
		c.Assert(err.Code, qt.Equals, test.expectCode)
		c.Assert(err, qt.ErrorMatches, test.expectError)
	}
}

type errorReader struct {
	Err error
}

func (r errorReader) Read(b []byte) (int, error) {
	return 0, r.Err
}
