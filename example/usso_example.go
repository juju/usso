package main

import (
	"encoding/json"
	"fmt"
	"launchpad.net/usso"
)

var email string
var password string
var tokenName string

func inputParams() {
	fmt.Println("This application will query the staging Ubuntu SSO Server to fetch authorisation tokens.")
	fmt.Print("Enter email: ")
	fmt.Scanf("%s", &email)
	fmt.Print("Enter password: ")
	fmt.Scanf("%s", &password)
	fmt.Print("Enter token name: ")
	fmt.Scanf("%s", &tokenName)
}

func main() {
	inputParams()
	fmt.Println("Fetching tokens from staging server...")
	server := usso.StagingUbuntuSSOServer
	// One would use server := usso.ProductionUbuntuSSOServer to use the production Ubuntu SSO Server.
	data, err := usso.GetToken(email, password, tokenName, server)
	if err != nil {
		panic(err)
	}
	// Format the token as json for displaying it.:
	json_data, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got tokens: %s\n", json_data)

}
