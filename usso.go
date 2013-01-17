package usso

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	// Initialize the random generator.
	rand.Seed(time.Now().UTC().UnixNano())
}

type Credentials struct {
	// Contains the user credentials used to get access token.
	Email        string `json:"email"`
	Password     string `json:"password"`
	TokenName    string `json:"token_name"`
	SSOServerURL string `json:"-"`
}

type SSOData struct {
	// Contains the 
	BaseURL        string
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	TokenKey       string `json:"token_key"`
	TokenName      string `json:"token_name"`
	TokenSecret    string `json:"token_secret"`
}

func GetToken(credentials *Credentials) (*SSOData, error) {
	// Get a valid access token from credentials.
	json_credentials, err := json.Marshal(credentials)
	if err != nil {
		log.Printf("Error: %s\n", err)
		return nil, err
	}
	response, err := http.Post(
		credentials.SSOServerURL,
		"application/json",
		strings.NewReader(string(json_credentials)))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	ssodata := SSOData{}
	err = json.Unmarshal(body, &ssodata)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &ssodata, nil
}

func (oauth *SSOData) Sign(req *http.Request) error {
	// Sign the provided request.
	auth := `OAuth realm="API", ` +
		`oauth_consumer_key="` + url.QueryEscape(oauth.ConsumerKey) + `", ` +
		`oauth_token="` + url.QueryEscape(oauth.TokenKey) + `", ` +
		`oauth_signature_method="PLAINTEXT", ` +
		`oauth_signature="` + url.QueryEscape(
		oauth.ConsumerSecret+`&`+oauth.TokenSecret) + `", ` +
		`oauth_timestamp="` + strconv.FormatInt(time.Now().Unix(), 10) + `", ` +
		`oauth_nonce="` + strconv.Itoa(int(rand.Intn(99999999))) + `", ` +
		`oauth_version="1.0"`
	req.Header.Add("Authorization", auth)
	return nil
}
