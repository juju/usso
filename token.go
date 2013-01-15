package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RequestBody struct {
	// Used to produce the request body
	Email     string `json:"email"`
	Password  string `json:"password"`
	TokenName string `json:"token_name"`
}

type ResponseBody struct {
	// Used to catch the values in the response body
	Secret    string `json:"secret"`
	Key       string `json:key`
	TokenName string `json:"token_name"`
}

func GetToken(email, password string) (*ResponseBody, error) {
	// Get a valid access token provided email and password
	msg := RequestBody{email, password, "juju"}
	json_msg, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	response, err := http.Post(
		"https://login.ubuntu.com/api/v2/tokens",
		"application/json",
		strings.NewReader(string(json_msg)))
	if err != nil {
		return nil, nil
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	response_body := ResponseBody{}
	err = json.Unmarshal(body, &response_body)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	return &response_body, nil
}

type OAuth struct {
	BaseURL     string
	Token       string
	TokenSecret string
	Consumer    string
}

func (oauth *OAuth) Sign(req *http.Request) error {
	auth := `OAuth realm="https://login.ubuntu.com/", ` +
		`oauth_consumer_key="` + url.QueryEscape(oauth.Consumer) + `", ` +
		`oauth_token="` + url.QueryEscape(oauth.Token) + `", ` +
		`oauth_signature_method="PLAINTEXT", ` +
		`oauth_signature="` + url.QueryEscape(`&`+oauth.TokenSecret) + `", ` +
		`oauth_timestamp="` + strconv.FormatInt(time.Now().Unix(), 10) + `", ` +
		`oauth_nonce="` + strconv.Itoa(int(rand.Int31())) + `", ` +
		`oauth_version="1.0"`
	req.Header.Add("Authorization", auth)
	return nil
}

func main() {
	// Just to test
	response_body, err := GetToken(
		"", "")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	fmt.Printf("Tokens: %+v\n", response_body)

	oauth := OAuth{
		"https://login.ubuntu.com/api/v2/accounts/vincenzo.di.somma%40canonical.com",
		response_body.Key,
		response_body.Secret,
		"login.ubuntu.com",
	}

	request, err := http.NewRequest(
		"POST",
		"https://login.ubuntu.com/api/v2/accounts/"+response_body.Key,
		nil)

	err = oauth.Sign(request)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	// run the request
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	fmt.Printf("response: %+v\n", response)
}
