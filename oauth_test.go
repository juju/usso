package usso

import (
	. "launchpad.net/gocheck"
	"net/http"
	"net/url"
)

func (suite *USSOTestSuite) TestSignRequestPlainText(c *C) {
	baseUrl := "https://localhost"
	ssodata := SSOData{BaseURL: baseUrl, ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, TokenKey: tokenKey,
		TokenName: tokenName, TokenSecret: tokenSecret}
	request, _ := http.NewRequest("GET", baseUrl, nil)
	ssodata.HTTPMethod = "GET"
	ssodata.SignatureMethod = "PLAINTEXT"
	err := ssodata.SignRequest(request)
	c.Assert(err, IsNil)
	authHeader := request.Header["Authorization"][0]
	c.Assert(authHeader, Matches, `^OAuth.*`)
	c.Assert(authHeader, Matches, `.*realm="API".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_token="`+url.QueryEscape(ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_signature="`+url.QueryEscape(
			ssodata.ConsumerSecret+`&`+ssodata.TokenSecret)+`.*`)
}

// Test the request signing with oauth_signature_method = SHA1
func (suite *USSOTestSuite) TestSignRequestSHA1(c *C) {
	baseUrl := "https://localhost"
	ssodata := SSOData{BaseURL: baseUrl, ConsumerKey: consumerKey,
		ConsumerSecret: consumerSecret, TokenKey: tokenKey,
		TokenName: tokenName, TokenSecret: tokenSecret,
		Nonce: "10888885", Timestamp: "1358853126"}
	request, _ := http.NewRequest("GET", baseUrl, nil)
	ssodata.HTTPMethod = "GET"
	ssodata.SignatureMethod = "HMAC-SHA1"
	err := ssodata.SignRequest(request)
	c.Assert(err, IsNil)
	authHeader := request.Header["Authorization"][0]
	c.Assert(authHeader, Matches, `^OAuth.*`)
	c.Assert(authHeader, Matches, `.*realm="API".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_token="`+url.QueryEscape(ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, Matches,
		`.*oauth_signature="`+"amJnYeek4G9ObTgTiE2y6cwTyPg="+`.*`)
}
