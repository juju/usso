// Copyright 2013 Canonical Ltd.  This software is licensed under the
// GNU Affero General Public License version 3 (see the file LICENSE).

package usso

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
)

func return_tokens(w http.ResponseWriter, request *http.Request) {
	// Utility function to test GetToken
	body, _ := ioutil.ReadAll(request.Body)
	if string(body) != `{"email":"foo@bar.com","password":"foobarpwd",`+
		`"token_name":"token_name"}` {
		log.Fatalf("Wrong Credential sent to server.\n")
	}
	io.WriteString(
		w,
		`{
		 "token_name": "foo", 
		 "date_updated": "2013-01-16 14:03:36", 
		 "token_key": "abcs", 
		 "consumer_secret": "rwDkQkkdfdfdeAslkmmxAOjOAT", 
		 "href": "/api/v2/tokens/abcd", 
		 "date_created": "2013-01-16 14:03:36", 
		 "consumer_key": "rfyzhdQ", 
		 "token_secret": "mTBgLxtTRUdfqewqgrqsvxlijbMWkPBajgKcoZCrDwv"
		 }`)
}

func TestGetToken(test *testing.T) {
	// Test that GetToken connects to the right
	http.HandleFunc("/", return_tokens)
	go http.ListenAndServe(":8123", nil)
	creds := Credentials{
		"foo@bar.com",
		"foobarpwd",
		"token_name",
		"http://localhost:8123"}
	ssodata, _ := GetToken(&creds)
	if ssodata.ConsumerKey != "rfyzhdQ" {
		test.Fatalf("Wrong consumer key: %s", ssodata.ConsumerKey)
	}
	if ssodata.ConsumerSecret != "rwDkQkkdfdfdeAslkmmxAOjOAT" {
		test.Fatalf("Wrong consumer secret: %s", ssodata.ConsumerSecret)
	}
	if ssodata.TokenKey != "abcs" {
		test.Fatalf("Wrong token key: %s", ssodata.TokenKey)
	}
	if ssodata.TokenName != "foo" {
		test.Fatalf("Wrong token name: %s", ssodata.TokenName)
	}
	if ssodata.TokenSecret != "mTBgLxtTRUdfqewqgrqsvxlijbMWkPBajgKcoZCrDwv" {
		test.Fatalf("Wrong Token secret: %s", ssodata.TokenSecret)
	}
}

func TestSignRequest(test *testing.T) {
	// Test SignRequest

	test_items := [...]string{
		`OAuth realm="API"`,
		`oauth_consumer_key="rfyzhdQ"`,
		`oauth_token="abcs"`,
		`oauth_signature="rwDkQkkdfdfdeAslkmmxAOjOAT%26mTBgLxtTRUdfqewqgrqsvx` +
			`lijbMWkPBajgKcoZCrDwv"`}

	creds := Credentials{
		"foo@bar.com",
		"foobarpwd",
		"token_name",
		"http://localhost:8123"}
	ssodata, _ := GetToken(&creds)
	ssodata.BaseURL = "https://login.staging.ubuntu.com/api/v2/accounts/"
	request, _ := http.NewRequest(
		"GET",
		"https://login.staging.ubuntu.com/api/v2/accounts/"+ssodata.ConsumerKey,
		nil)
	ssodata.Sign(request)
	if !strings.Contains(
		request.Header["Authorization"][0],
		`OAuth realm="API"`) {
		test.Fail()
	}

	for _, c := range test_items {
		if !strings.Contains(
			request.Header["Authorization"][0],
			c) {
			test.Fail()
		}
	}
}
