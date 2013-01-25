package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"launchpad.net/usso"
	"net/http"
)

var email, password, tokenName, signature_method string

func inputParams() {
	fmt.Println("This application will query the staging Ubuntu SSO Server" +
		" to fetch authorisation tokens.")
	fmt.Print("Enter email: ")
	fmt.Scanf("%s", &email)
	fmt.Print("Enter password: ")
	fmt.Scanf("%s", &password)
	fmt.Print("Enter token name: ")
	fmt.Scanf("%s", &tokenName)
	fmt.Print("Enter signature method (PLAINTEXT or HMAC-SHA1): ")
	fmt.Scanf("%s", &signature_method)
}

func main() {
	inputParams()

	// Fetch the tokens using usso.GetToken.
	fmt.Println("Fetching tokens from staging server...")
	server := usso.StagingUbuntuSSOServer
	// One would use server := usso.ProductionUbuntuSSOServer 
	// to use the production Ubuntu SSO Server.
	ssodata, err := server.GetToken(email, password, tokenName)
	if err != nil {
		panic(err)
	}
	// Format the result as json for displaying it:
	json_token, err := json.Marshal(ssodata)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got tokens: %s\n", json_token)

	ssodata.BaseURL = fmt.Sprintf(
		"https://login.staging.ubuntu.com/api/v2/accounts/%s",
		ssodata.ConsumerKey)
	ssodata.HTTPMethod = "GET"
	ssodata.SignatureMethod = signature_method
	request, _ := http.NewRequest(ssodata.HTTPMethod, ssodata.BaseURL, nil)
	usso.SignRequest(ssodata, request)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	// run the request
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
	}
	var b bytes.Buffer
	b.Write(body)
	fmt.Printf("response: %+v\n", b.String())
}
