package usso

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	. "launchpad.net/gocheck"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test(test *testing.T) { TestingT(test) }

type USSOTestSuite struct{}

var _ = Suite(&USSOTestSuite{})

const (
	tokenName      = "foo"
	tokenKey       = "abcs"
	tokenSecret    = "mTBgLxtTRUdfqewqgrqsvxlijbMWkPBajgKcoZCrDwv"
	consumerKey    = "rfyzhdQ"
	consumerSecret = "rwDkQkkdfdfdeAslkmmxAOjOAT"
	email          = "foo@bar.com"
	password       = "foobarpwd"
)

type SingleServingServer struct {
	*httptest.Server
	requestContent *string
}

// TestProductionUbuntuSSOServerURLs tests the URLs of the production server.
func (suite *USSOTestSuite) TestProductionUbuntuSSOServerURLs(c *C) {
	tokenURL := ProductionUbuntuSSOServer.tokenURL()
	c.Assert(tokenURL, Equals, "https://login.ubuntu.com/api/v2/tokens/oauth")
}

// TestStagingUbuntuSSOServerURLs tests the URLs of the staging server.
func (suite *USSOTestSuite) TestStagingUbuntuSSOServerURLs(c *C) {
	tokenURL := StagingUbuntuSSOServer.tokenURL()
	c.Assert(tokenURL, Equals, "https://login.staging.ubuntu.com/api/v2/tokens/oauth")
}

// newSingleServingServer create a single-serving test http server which will
// return only one response as defined by the passed arguments.
func newSingleServingServer(
	uri string, response string, code int) *SingleServingServer {
	var requestContent string
	var requested bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		if requested {
			http.Error(w, "Already requested", http.StatusServiceUnavailable)
		}
		res, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		requestContent = string(res)
		if r.URL.String() != uri || strings.Contains(requestContent, "WRONG") {
			http.Error(w, "404 page not found", http.StatusNotFound)
		} else {
			w.WriteHeader(code)
			fmt.Fprint(w, response)
		}
		requested = true
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	return &SingleServingServer{server, &requestContent}
}

func (suite *USSOTestSuite) TestGetTokenReturnsTokens(c *C) {
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
	server := newSingleServingServer("/api/v2/tokens/oauth",
		string(jsonServerResponseData), 200)
	var testSSOServer = &UbuntuSSOServer{server.URL}
	defer server.Close()

	// The returned information is correct.
	ssodata, err := testSSOServer.GetToken(email, password, tokenName)
	c.Assert(err, IsNil)
	expectedSSOData := &SSOData{ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, TokenKey: tokenKey,
		TokenSecret: tokenSecret, TokenName: tokenName}
	c.Assert(ssodata, DeepEquals, expectedSSOData)
	//The request that the fake Ubuntu SSO Server got contained the credentials.
	credentials := map[string]string{
		"email":      email,
		"password":   password,
		"token_name": tokenName,
	}
	expectedRequestContent, err := json.Marshal(credentials)
	if err != nil {
		panic(err)
	}
	c.Assert(*server.requestContent, Equals, string(expectedRequestContent))
}

// GetToken should return empty credentials and an error, if wrong account is provided.
func (suite *USSOTestSuite) TestGetTokenFails(c *C) {
	server := newSingleServingServer("/api/v2/tokens/oauth", "{}", 200)
	var testSSOServer = &UbuntuSSOServer{server.URL}
	defer server.Close()
	ssodata, err := testSSOServer.GetToken(email, "WRONG", tokenName)
	fmt.Println(ssodata, err)
	c.Assert(err, NotNil)
	c.Assert(ssodata, IsNil)
}
