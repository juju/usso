// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENSE file for details.

package usso

import (
	"net/http"
	"net/url"
	"testing"

	qt "github.com/frankban/quicktest"
)

func defaults(c *qt.C) (SSOData, RequestParameters, *http.Request) {
	baseUrl := "https://localhost"
	ssodata := SSOData{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
		Realm:          realm,
		TokenKey:       tokenKey,
		TokenName:      tokenName,
		TokenSecret:    tokenSecret,
	}
	rp := RequestParameters{
		BaseURL:    "https://localhost",
		HTTPMethod: "GET",
		Nonce:      "10888885",
		Timestamp:  "1358853126",
	}
	req, err := http.NewRequest("GET", baseUrl, nil)
	c.Assert(err, qt.Equals, nil)

	return ssodata, rp, req
}

// It is possible to sign a request with oauth_signature_method = PLAINTEXT
func TestSignRequestPlainText(t *testing.T) {
	c := qt.New(t)

	ssodata, rp, req := defaults(c)
	rp.SignatureMethod = PLAINTEXT{}
	err := ssodata.SignRequest(&rp, req)
	c.Assert(err, qt.Equals, nil)

	authHeader := req.Header.Get("Authorization")
	c.Assert(authHeader, qt.Matches, `^OAuth.*`)
	c.Assert(authHeader, qt.Matches, `.*realm="API".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_token="`+url.QueryEscape(ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_signature="`+url.QueryEscape(ssodata.ConsumerSecret)+`&`+url.QueryEscape(ssodata.TokenSecret)+`.*`)
}

// It is possible to sign a request  with oauth_signature_method = SHA1
func TestSignRequestSHA1(t *testing.T) {
	c := qt.New(t)

	ssodata, rp, req := defaults(c)
	rp.SignatureMethod = HMACSHA1{}
	err := ssodata.SignRequest(&rp, req)
	c.Assert(err, qt.Equals, nil)

	authHeader := req.Header.Get("Authorization")
	c.Assert(authHeader, qt.Matches, `^OAuth.*`)
	c.Assert(authHeader, qt.Matches, `.*realm="API".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_token="`+url.QueryEscape(ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_signature="`+"amJnYeek4G9ObTgTiE2y6cwTyPg="+`.*`)
}

func TestSignRequestSHA1WithParams(t *testing.T) {
	c := qt.New(t)

	ssodata, rp, req := defaults(c)
	rp.SignatureMethod = HMACSHA1{}
	rp.Params = url.Values{
		"a": []string{"B", "A"},
		"z": []string{""},
	}
	err := ssodata.SignRequest(&rp, req)
	c.Assert(err, qt.Equals, nil)

	authHeader := req.Header.Get("Authorization")
	c.Assert(authHeader, qt.Matches, `^OAuth.*`)
	c.Assert(authHeader, qt.Matches, `.*realm="API".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_consumer_key="`+url.QueryEscape(ssodata.ConsumerKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_token="`+url.QueryEscape(ssodata.TokenKey)+`".*`)
	c.Assert(authHeader, qt.Matches,
		`.*oauth_signature="`+"a/PwZ4HMX0FptNA4KRFl1jIqlOg="+`.*`)
}
