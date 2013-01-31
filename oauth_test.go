package usso

import (
	. "launchpad.net/gocheck"
	"net/http"
	"net/url"
)

type OAuthTestSuite struct {
	ssodata SSOData
	rp      RequestParameters
	request *http.Request
}

var _ = Suite(&OAuthTestSuite{})

func (suite *OAuthTestSuite) SetUpTest(c *C) {
	baseUrl := "https://localhost"
	suite.ssodata = SSOData{ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, TokenKey: tokenKey,
		TokenName: tokenName, TokenSecret: tokenSecret}
	suite.rp = RequestParameters{BaseURL: baseUrl, HTTPMethod: "GET",
		Nonce: "10888885", Timestamp: "1358853126"}
	suite.request, _ = http.NewRequest("GET", baseUrl, nil)
}

// Test the request signing with oauth_signature_method = PLAINTEXT
func (suite *OAuthTestSuite) TestSignRequestPlainText(c *C) {
	// FIXME use rp SignatureMethod
	suite.rp.SignatureMethod = PLAINTEXT{}
	err := suite.ssodata.SignRequest(&suite.rp, suite.request)
	if err != nil {
		c.Log(err)
		c.FailNow()
	}
	authHeader := suite.request.Header["Authorization"][0]
	c.Assert(authHeader, Matches, `^OAuth.*`)
	c.Assert(authHeader, Matches, `.*realm="API".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(
			suite.ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_token="`+url.QueryEscape(suite.ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_signature="`+url.QueryEscape(
			suite.ssodata.ConsumerSecret)+`&`+url.QueryEscape(
			suite.ssodata.TokenSecret)+`.*`)
}

// Test the request signing with oauth_signature_method = SHA1
func (suite *OAuthTestSuite) TestSignRequestSHA1(c *C) {
	// FIXME use rp SignatureMethod
	suite.rp.SignatureMethod = HMACSHA1{}
	err := suite.ssodata.SignRequest(&suite.rp, suite.request)
	if err != nil {
		c.Log(err)
		c.FailNow()
	}
	authHeader := suite.request.Header["Authorization"][0]
	c.Assert(authHeader, Matches, `^OAuth.*`)
	c.Assert(authHeader, Matches, `.*realm="API".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(
			suite.ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_token="`+url.QueryEscape(suite.ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_signature="`+"amJnYeek4G9ObTgTiE2y6cwTyPg="+`.*`)
}
