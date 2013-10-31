package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"launchpad.net/usso"
	"net/http"
)

var email, password string

func inputParams() {
	fmt.Println("This application will query the staging Ubuntu SSO Server" +
		" to fetch authorisation tokens.")
	fmt.Print("Enter email: ")
	fmt.Scanf("%s", &email)
	fmt.Print("Enter password: ")
	fmt.Scanf("%s", &password)
	fmt.Print("Enter token name: ")
}

func main() {
	inputParams()
	// Fetch the tokens using usso.GetToken.
	fmt.Println("Fetching tokens from staging server...")
	server := usso.StagingUbuntuSSOServer
	ssodata, err := server.GetToken(email, password, "usso")
	if err != nil {
		panic(err)
	}
	// Format the result as json for displaying it:
	json_token, err := json.Marshal(ssodata)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got tokens: %s\n", json_token)

	// This would be the easiest way to get the account data.
	//accounts, _ := server.GetAccounts(ssodata)
	//fmt.Printf("Got accounts info: %s\n", accounts)

	// But this shows how to sign a generic request.
	rp := usso.RequestParameters{BaseURL: fmt.Sprintf(
		"https://login.staging.ubuntu.com/api/v2/accounts/%s",
		ssodata.ConsumerKey), HTTPMethod: "GET",
		SignatureMethod: usso.HMACSHA1{}}
	request, _ := http.NewRequest(rp.HTTPMethod, rp.BaseURL, nil)
	usso.SignRequest(ssodata, &rp, request)
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
	token_details, _ := server.GetTokenDetails(ssodata)
	fmt.Printf("token details: %s\n", token_details)
}
