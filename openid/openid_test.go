// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENSE file for details.

package openid_test

import (
	"errors"
	"net/url"
	"testing"

	qt "github.com/frankban/quicktest"
	yopenid "github.com/yohcop/openid-go"
	"gopkg.in/errgo.v1"
	macaroon "gopkg.in/macaroon.v2"

	"github.com/juju/usso"
	"github.com/juju/usso/openid"
)

type openidSuite struct {
}

var redirectURLTests = []struct {
	about   string
	server  usso.UbuntuSSOServer
	request *openid.Request
	expect  string
}{{
	about:  "production-with-only-return_to",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo: "http://return.to",
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to",
}, {
	about:  "staging-with-only-return_to",
	server: usso.StagingUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo: "http://return.to",
	},
	expect: "https://login.staging.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to",
}, {
	about:  "with-realm",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo: "http://return.to/abcdef",
		Realm:    "http://return.to",
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to/abcdef&openid.realm=http://return.to",
}, {
	about:  "with-teams",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo: "http://return.to",
		Teams:    []string{"team1", "team2"},
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to&openid.ns.lp=http://ns.launchpad.net/2007/openid-teams&openid.lp.query_membership=team1,team2",
}, {
	about:  "with sreg.required",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo:     "http://return.to",
		SRegRequired: []string{openid.SRegEmail, openid.SRegProvince},
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to&openid.ns.sreg=http://openid.net/extensions/sreg/1.1&openid.sreg.required=email,x_province",
}, {
	about:  "with-sreg.optional",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo:     "http://return.to",
		SRegOptional: []string{openid.SRegNickname, openid.SRegCity},
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to&openid.ns.sreg=http://openid.net/extensions/sreg/1.1&openid.sreg.optional=nickname,x_city",
}, {
	about:  "with-sreg",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo:     "http://return.to",
		SRegRequired: []string{openid.SRegEmail, openid.SRegProvince},
		SRegOptional: []string{openid.SRegNickname, openid.SRegCity},
	},
	expect: "https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to&openid.ns.sreg=http://openid.net/extensions/sreg/1.1&openid.sreg.required=email,x_province&openid.sreg.optional=nickname,x_city",
}, {
	about:  "with-caveat",
	server: usso.ProductionUbuntuSSOServer,
	request: &openid.Request{
		ReturnTo: "http://return.to",
		CaveatID: `{"secret": "squirrel", "version": 1}`,
	},
	expect: `https://login.ubuntu.com/+openid?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=http://return.to&openid.ns.macaroon=http://ns.login.ubuntu.com/2016/openid-macaroon&openid.macaroon.caveat_id={"secret": "squirrel", "version": 1}`,
}}

func TestRedirectURL(t *testing.T) {
	c := qt.New(t)

	for _, test := range redirectURLTests {
		c.Run(test.about, func(c *qt.C) {
			client := openid.NewClient(test.server, nil, nil)
			u, err := url.Parse(client.RedirectURL(test.request))
			c.Assert(err, qt.Equals, nil)
			expectURL, err := url.Parse(test.expect)
			c.Assert(err, qt.Equals, nil)
			query := u.Query()
			expectQuery := expectURL.Query()
			c.Assert(query, qt.DeepEquals, expectQuery)
			u.RawQuery = ""
			expectURL.RawQuery = ""
			c.Assert(u, qt.DeepEquals, expectURL)
		})
	}
}

var verifyTests = []struct {
	about            string
	url              string
	server           usso.UbuntuSSOServer
	nonceStore       yopenid.NonceStore
	discoveryCache   yopenid.DiscoveryCache
	verifyF          func(*qt.C, string, yopenid.DiscoveryCache, yopenid.NonceStore) (string, error)
	expectResponse   *openid.Response
	expectError      string
	expectErrorCause error
}{{
	about:   "id only",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
	},
}, {
	about:   "teams",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity,lp.is_member&openid.sig=AAAA&openid.ns.lp=http://ns.launchpad.net/2007/openid-teams&openid.lp.is_member=team1,team2",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID:    "https://login.ubuntu.com/+id/AAAAAA",
		Teams: []string{"team1", "team2"},
	},
}, {
	about:   "simple-registration",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity,sreg.email,sreg.fullname&openid.sig=AAAA&openid.ns.sreg=http://openid.net/extensions/sreg/1.1&openid.sreg.email=a@example.org&openid.sreg.fullname=A",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
		SReg: map[string]string{
			openid.SRegEmail:    "a@example.org",
			openid.SRegFullName: "A",
		},
	},
}, {
	about:   "teams-not-signed",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA&openid.ns.lp=http://ns.launchpad.net/2007/openid-teams&openid.lp.is_member=team1,team2",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
	},
}, {
	about:   "simple-registration-not-signed",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA&openid.ns.sreg=http://openid.net/extensions/sreg/1.1&openid.sreg.email=a@example.org&openid.sreg.fullname=A",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
	},
}, {
	about:       "bad-url",
	url:         "://return.to",
	server:      usso.ProductionUbuntuSSOServer,
	verifyF:     verifySuccess,
	expectError: `parse "://return.to": missing protocol scheme`,
}, {
	about:       "unexpected-OP",
	url:         "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA",
	server:      usso.StagingUbuntuSSOServer,
	verifyF:     verifySuccess,
	expectError: `OpenID response from unexpected endpoint "https://login.ubuntu.com/\+openid"`,
}, {
	about:  "verification-failure",
	url:    "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA",
	server: usso.ProductionUbuntuSSOServer,
	verifyF: func(*qt.C, string, yopenid.DiscoveryCache, yopenid.NonceStore) (string, error) {
		return "", errors.New("TEST!")
	},
	expectError: `TEST!`,
}, {
	about:      "uses-specified-NonceStore",
	url:        "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA",
	server:     usso.ProductionUbuntuSSOServer,
	nonceStore: testNonceStore,
	verifyF: func(c *qt.C, _ string, _ yopenid.DiscoveryCache, ns yopenid.NonceStore) (string, error) {
		c.Assert(ns, qt.Equals, testNonceStore)
		return "PASS", nil
	},
	expectResponse: &openid.Response{
		ID: "PASS",
	},
}, {
	about:  "creates-server-specific-DiscoveryCache",
	url:    "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity&openid.sig=AAAA",
	server: usso.ProductionUbuntuSSOServer,
	verifyF: func(c *qt.C, _ string, dc yopenid.DiscoveryCache, _ yopenid.NonceStore) (string, error) {
		c.Assert(dc, qt.Not(qt.IsNil))
		di := dc.Get("https://login.ubuntu.com/+id/AAAAAA")
		c.Assert(di, qt.Not(qt.IsNil))
		c.Assert(di.ClaimedID(), qt.Equals, "https://login.ubuntu.com/+id/AAAAAA")
		c.Assert(di.OpLocalID(), qt.Equals, "https://login.ubuntu.com/+id/AAAAAA")
		c.Assert(di.OpEndpoint(), qt.Equals, "https://login.ubuntu.com/+openid")
		di = dc.Get("https://login.staging.ubuntu.com/+id/AAAAAA")
		c.Assert(di, qt.IsNil)
		return "PASS", nil
	},
	expectResponse: &openid.Response{
		ID: "PASS",
	},
}, {
	about: "cancel-response",
	url:   "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=cancel",
	verifyF: func(c *qt.C, _ string, _ yopenid.DiscoveryCache, _ yopenid.NonceStore) (string, error) {
		c.Fatalf("verify should not have been called")
		panic("unreachable")
	},
	expectError:      "login cancelled",
	expectErrorCause: openid.ErrCancel,
}, {
	about: "bad-mode",
	url:   "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=bad",
	verifyF: func(c *qt.C, _ string, _ yopenid.DiscoveryCache, _ yopenid.NonceStore) (string, error) {
		c.Fatalf("verify should not have been called")
		panic("unreachable")
	},
	expectError: `unrecognised mode "bad"`,
}, {
	about: "openid-error",
	url:   "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=error&openid.error=test+message&openid.contact=test+contact&openid.reference=test+reference",
	verifyF: func(c *qt.C, _ string, _ yopenid.DiscoveryCache, _ yopenid.NonceStore) (string, error) {
		c.Fatalf("verify should not have been called")
		panic("unreachable")
	},
	expectError: `test message`,
	expectErrorCause: &openid.OpenIDError{
		Message:   "test message",
		Contact:   "test contact",
		Reference: "test reference",
	},
}, {
	about:   "discharge",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity,macaroon.discharge&openid.sig=AAAA&openid.ns.macaroon=http://ns.login.ubuntu.com/2016/openid-macaroon&openid.macaroon.discharge=MDAwZWxvY2F0aW9uIAowMDE0aWRlbnRpZmllciBUZXN0CjAwMmZzaWduYXR1cmUgHF1XmyS2hpzHuObgmCBWFzpF7U0hFRuLnDsfkGLG9kAK",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID:        "https://login.ubuntu.com/+id/AAAAAA",
		Discharge: testMacaroon,
	},
}, {
	about:   "discharge-bad-base64",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity,macaroon.discharge&openid.sig=AAAA&openid.ns.macaroon=http://ns.login.ubuntu.com/2016/openid-macaroon&openid.macaroon.discharge=MDAwZWxvY2F0aW9uIAowMDE0aWRlbnRpZmllciBUZXN0CjAwMmZzaWduYXR1cmUgHF1XmyS2hpzHuObgmCBWFzpF7U0hFRuLnDsfkGLG9kA:",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
	},
}, {
	about:   "discharge-invalid-macaroon",
	url:     "http://return.to?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.op_endpoint=https://login.ubuntu.com/%2Bopenid&openid.claimed_id=https://login.ubuntu.com/%2Bid/AAAAAA&openid.identity=https://login.ubuntu.com/%2Bid/AAAAAA&openid.return_to=http://return.to&openid.response_nonce=2005-05-15T17:11:51ZUNIQUE&openid.assoc_handle=1&openid.signed=op_endpoint,return_to,response_nonce,assoc_handle,claimed_id,identity,macaroon.discharge&openid.sig=AAAA&openid.ns.macaroon=http://ns.login.ubuntu.com/2016/openid-macaroon&openid.macaroon.discharge=NDAwZWxvY2F0aW9uIAowMDE0aWRlbnRpZmllciBUZXN0CjAwMmZzaWduYXR1cmUgHF1XmyS2hpzHuObgmCBWFzpF7U0hFRuLnDsfkGLG9kAK",
	server:  usso.ProductionUbuntuSSOServer,
	verifyF: verifySuccess,
	expectResponse: &openid.Response{
		ID: "https://login.ubuntu.com/+id/AAAAAA",
	},
}}

var testMacaroon = func() *macaroon.Macaroon {
	m, err := macaroon.New([]byte("A"), []byte("Test"), "", macaroon.V1)
	if err != nil {
		panic(err)
	}
	return m
}()

func TestVerify(t *testing.T) {
	c := qt.New(t)

	for _, test := range verifyTests {
		c.Run(test.about, func(c *qt.C) {
			*openid.Verify = func(s string, dc yopenid.DiscoveryCache, ns yopenid.NonceStore) (string, error) {
				return test.verifyF(c, s, dc, ns)
			}
			client := openid.NewClient(test.server, test.nonceStore, test.discoveryCache)
			r, err := client.Verify(test.url)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				if test.expectErrorCause != nil {
					c.Assert(errgo.Cause(err), qt.DeepEquals, test.expectErrorCause)
				}
				return
			}
			c.Assert(err, qt.Equals, nil)
			c.Assert(r, qt.DeepEquals, test.expectResponse)
		})
	}
}

func verifySuccess(_ *qt.C, s string, _ yopenid.DiscoveryCache, _ yopenid.NonceStore) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	return u.Query().Get("openid.claimed_id"), nil
}

var testNonceStore = yopenid.NewSimpleNonceStore()
