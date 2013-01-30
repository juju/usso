package usso

import (
	. "launchpad.net/gocheck"
	"net/http"
	"net/url"
)

type OAuthTestSuite struct {
	ssodata SSOData
	request *http.Request
}

var _ = Suite(&OAuthTestSuite{})

func (suite *OAuthTestSuite) SetUpTest(c *C) {
	baseUrl := "https://localhost"
	suite.ssodata = SSOData{BaseURL: baseUrl, ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, TokenKey: tokenKey,
		TokenName: tokenName, TokenSecret: tokenSecret,
		Nonce: "10888885", Timestamp: "1358853126"}
	suite.request, _ = http.NewRequest("GET", baseUrl, nil)
	suite.ssodata.HTTPMethod = "GET"
}

func (suite *OAuthTestSuite) TestSignRequestPlainText(c *C) {
	suite.ssodata.SignatureMethod = "PLAINTEXT"
	err := suite.ssodata.SignRequest(suite.request)
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
			suite.ssodata.ConsumerSecret+`&`+suite.ssodata.TokenSecret)+`.*`)
}

// Test the request signing with oauth_signature_method = SHA1
func (suite *OAuthTestSuite) TestSignRequestSHA1(c *C) {
	suite.ssodata.SignatureMethod = "HMAC-SHA1"
	err := suite.ssodata.SignRequest(suite.request)
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

// Test the request signing with BAD oauth_signature_method
func (suite *OAuthTestSuite) TestSignRequestBad(c *C) {
	suite.ssodata.SignatureMethod = "XXX"
	// "XXX" is not a supported oauth_signature_method
	err := suite.ssodata.SignRequest(suite.request)
	// Test that the error has being raised
	if err.Error() != "usso/oauth: Oauth Signature Method not supported." {
		// If there is no error the test fails
		c.Failed()
	}
}
