package fiware

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	//"github.com/tomnomnom/linkheader"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"encoding/base64"

	"github.com/rancher/rancher-auth-service/model"
)

const (
	gheAPI                = "/api/v3"
	fiwareAccessToken     = Name + "access_token"
	fiwareAPI             = "https://account.lab.fiware.org"
	fiwareDefaultHostName = "https://account.lab.fiware.org"
)

//FClient implements a httpclient for fiware
type FClient struct {
	httpClient *http.Client
	config     *model.FiwareConfig
}

func (g *FClient) getAccessToken(code string) (string, error) {
	form := url.Values{}
	form.Add("client_id", g.config.ClientID)
	form.Add("client_secret", g.config.ClientSecret)
	form.Add("code", code)
	form.Add("grant_type", "authorization_code")
	//form.Add("redirect_uri", g.config.Scheme + g.config.Hostname)
	form.Add("redirect_uri", g.config.RedirectURI)

	url := g.getURL("TOKEN")

	resp, err := g.postToFiware(url, form)
	if err != nil {
		log.Errorf("Fiware getAccessToken: GET url %v received error from fiware, err: %v", url, err)
		return "", err
	}
	defer resp.Body.Close()
	log.Errorf("Received resp to getAccessCode: %v", resp)

	// Decode the response
	var respMap map[string]interface{}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Fiware getAccessToken: received error reading response body, err: %v", err)
		return "", err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		log.Errorf("Fiware getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", err
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		log.Errorf("Received Error from fiware %v, description from fiware %v", respMap["error"], desc)
		return "", fmt.Errorf("Received Error from fiware %v, description from fiware %v", respMap["error"], desc)
	}

	acessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}
	return acessToken, nil
}

func (g *FClient) getFiwareUser(fiwareAccessToken string) (Account, error) {

	url := g.getURL("USER_INFO")
	resp, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getFiwareUser: GET url %v received error from fiware, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var fiwareAcct Account
	
	log.Errorf("Received resp to getFiwareUser: %v", resp)
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Fiware getFiwareUser: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &fiwareAcct); err != nil {
		log.Errorf("Fiware getFiwareUser: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return fiwareAcct, nil
}

func (g *FClient) getFiwareUserByName(username string, fiwareAccessToken string) (Account, error) {
	return Account{ID: username, Login: username, Name: username, AvatarURL: "", HTMLURL: ""}, nil
}

func (g *FClient) getUserOrgByID(id string, fiwareAccessToken string) (Account, error) {
	return Account{ID: id, Login: id, Name: id, AvatarURL: "", HTMLURL: ""}, nil
}

//URLEncoded encodes the string
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		log.Errorf("Error encoding the url: %s, error: %v", str, err)
		return str
	}
	return u.String()
}

func (g *FClient) postToFiware(url string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		log.Error(err)
	}
	req.PostForm = form
	auth := base64.StdEncoding.EncodeToString([]byte(g.config.ClientID+":"+g.config.ClientSecret))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	log.Error("Doing post request: %v", req)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Errorf("Received error from fiware: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (g *FClient) getFromFiware(fiwareAccessToken string, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url+"?access_token="+fiwareAccessToken, nil)
	if err != nil {
		log.Error(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)")
	log.Errorf("Doing get request: %v", req)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Errorf("Received error from fiware: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (g *FClient) getURL(endpoint string) string {

	var hostName, apiEndpoint, toReturn string

	if g.config.Hostname != "" {
		hostName = fiwareDefaultHostName
		apiEndpoint = fiwareAPI
	} else {
		hostName = fiwareDefaultHostName
		apiEndpoint = fiwareAPI
	}

	switch endpoint {
	case "API":
		toReturn = apiEndpoint
	case "TOKEN":
		toReturn = hostName + "/oauth2/token"
	case "USER_INFO":
		toReturn = apiEndpoint + "/user"
	default:
		toReturn = apiEndpoint
	}

	return toReturn
}
