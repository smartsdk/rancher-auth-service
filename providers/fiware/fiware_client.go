package fiware

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/tomnomnom/linkheader"
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

//GClient implements a httpclient for fiware
type GClient struct {
	httpClient *http.Client
	config     *model.FiwareConfig
}

func (g *GClient) getAccessToken(code string) (string, error) {
	form := url.Values{}
	form.Add("client_id", g.config.ClientID)
	form.Add("client_secret", g.config.ClientSecret)
	form.Add("code", code)
	form.Add("grant_type", "authorization_code")
	form.Add("redirect_uri", g.config.Scheme + g.config.Hostname)

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

func (g *GClient) getFiwareUser(fiwareAccessToken string) (Account, error) {

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

func (g *GClient) getFiwareOrgs(fiwareAccessToken string) ([]Account, error) {
	var orgs []Account
	url := g.getURL("ORG_INFO")
	responses, err := g.paginateFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getFiwareOrgs: GET url %v received error from fiware, err: %v", url, err)
		return orgs, err
	}

	for _, response := range responses {
		defer response.Body.Close()
		var orgObjs []Account
		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorf("Fiware getFiwareOrgs: error reading the response from fiware, err: %v", err)
			return orgs, err
		}
		if err := json.Unmarshal(b, &orgObjs); err != nil {
			log.Errorf("Fiware getFiwareOrgs: received error unmarshalling org array, err: %v", err)
			return orgs, err
		}
		for _, orgObj := range orgObjs {
			orgs = append(orgs, orgObj)
		}
	}

	return orgs, nil
}

func (g *GClient) getFiwareTeams(fiwareAccessToken string) ([]Account, error) {
	var teams []Account
	url := g.getURL("TEAMS")
	responses, err := g.paginateFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getFiwareTeams: GET url %v received error from fiware, err: %v", url, err)
		return teams, err
	}
	for _, response := range responses {
		defer response.Body.Close()
		teamObjs, err := g.getTeamInfo(response)

		if err != nil {
			log.Errorf("Fiware getFiwareTeams: received error unmarshalling teams array, err: %v", err)
			return teams, err
		}
		for _, teamObj := range teamObjs {
			teams = append(teams, teamObj)
		}

	}
	return teams, nil
}

func (g *GClient) getTeamInfo(response *http.Response) ([]Account, error) {
	var teams []Account
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Fiware getTeamInfo: error reading the response from fiware, err: %v", err)
		return teams, err
	}
	var teamObjs []Team
	if err := json.Unmarshal(b, &teamObjs); err != nil {
		log.Errorf("Fiware getTeamInfo: received error unmarshalling team array, err: %v", err)
		return teams, err
	}
	url := g.getURL("TEAM_PROFILE")
	for _, team := range teamObjs {
		teamAcct := Account{}
		team.toFiwareAccount(url, &teamAcct)
		teams = append(teams, teamAcct)
	}

	return teams, nil
}

func (g *GClient) getTeamByID(id string, fiwareAccessToken string) (Account, error) {
	var teamAcct Account
	url := g.getURL("TEAM") + id
	response, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getTeamByID: GET url %v received error from fiware, err: %v", url, err)
		return teamAcct, err
	}
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Fiware getTeamByID: error reading the response from fiware, err: %v", err)
		return teamAcct, err
	}
	var teamObj Team
	if err := json.Unmarshal(b, &teamObj); err != nil {
		log.Errorf("Fiware getTeamByID: received error unmarshalling team array, err: %v", err)
		return teamAcct, err
	}
	url = g.getURL("TEAM_PROFILE")
	teamObj.toFiwareAccount(url, &teamAcct)

	return teamAcct, nil
}

func (g *GClient) paginateFiware(fiwareAccessToken string, url string) ([]*http.Response, error) {
	var responses []*http.Response

	response, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		return responses, err
	}
	responses = append(responses, response)
	nextURL := g.nextFiwarePage(response)
	for nextURL != "" {
		response, err = g.getFromFiware(fiwareAccessToken, nextURL)
		if err != nil {
			return responses, err
		}
		responses = append(responses, response)
		nextURL = g.nextFiwarePage(response)
	}

	return responses, nil
}

func (g *GClient) nextFiwarePage(response *http.Response) string {
	header := response.Header.Get("link")

	if header != "" {
		links := linkheader.Parse(header)
		for _, link := range links {
			if link.Rel == "next" {
				return link.URL
			}
		}
	}

	return ""
}

func (g *GClient) getFiwareUserByName(username string, fiwareAccessToken string) (Account, error) {
	
	/*
	_, err := g.getFiwareOrgByName(username, fiwareAccessToken)
	if err == nil {
		return Account{}, fmt.Errorf("There is a org by this name, not looking fo the user entity by name %v", username)
	}
	*/
	
	return Account{ID: username, Login: username, Name: username, AvatarURL: "", HTMLURL: ""}, nil

	username = URLEncoded(username)
	url := g.getURL("USERS") + username

	resp, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getFiwareUserByName: GET url %v received error from fiware, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var fiwareAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Fiware getFiwareUserByName: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &fiwareAcct); err != nil {
		log.Errorf("Fiware getFiwareUserByName: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return fiwareAcct, nil
}

func (g *GClient) getFiwareOrgByName(org string, fiwareAccessToken string) (Account, error) {

	org = URLEncoded(org)
	url := g.getURL("ORGS") + org

	resp, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getFiwareOrgByName: GET url %v received error from fiware, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var fiwareAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Fiware getFiwareOrgByName: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &fiwareAcct); err != nil {
		log.Errorf("Fiware getFiwareOrgByName: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return fiwareAcct, nil
}

func (g *GClient) getUserOrgByID(id string, fiwareAccessToken string) (Account, error) {

	return Account{ID: id, Login: id, Name: id, AvatarURL: "", HTMLURL: ""}, nil

	url := g.getURL("USER_INFO") + "/" + id

	resp, err := g.getFromFiware(fiwareAccessToken, url)
	if err != nil {
		log.Errorf("Fiware getUserOrgById: GET url %v received error from fiware, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var fiwareAcct Account

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Fiware getUserOrgById: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &fiwareAcct); err != nil {
		log.Errorf("Fiware getUserOrgById: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return fiwareAcct, nil
}

/* TODO non-exact search
func (g *FiwareClient) searchFiware(fiwareAccessToken string, url string) []map[string]interface{} {
	log.Debugf("url %v",url)
	resp, err := g.getFromFiware(fiwareAccessToken, url)
}


    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchFiware(String url) {
        try {
            HttpResponse res = getFromFiware(fiwareTokenUtils.getAccessToken(), url);
            //TODO:Finish implementing search.
            Map<String, Object> jsonData = jsonMapper.readValue(res.getEntity().getContent());
            return (List<Map<String, Object>>) jsonData.get("items");
        } catch (IOException e) {
            //TODO: Proper Error Handling.
            return new ArrayList<>();
        }
    }

*/

//URLEncoded encodes the string
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		log.Errorf("Error encoding the url: %s, error: %v", str, err)
		return str
	}
	return u.String()
}

func (g *GClient) postToFiware(url string, form url.Values) (*http.Response, error) {
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

func (g *GClient) getFromFiware(fiwareAccessToken string, url string) (*http.Response, error) {
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

func (g *GClient) getURL(endpoint string) string {

	var hostName, apiEndpoint, toReturn string

	if g.config.Hostname != "" {
		//hostName = g.config.Scheme + g.config.Hostname
		//apiEndpoint = g.config.Scheme + g.config.Hostname + gheAPI
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
	case "USERS":
		toReturn = apiEndpoint + "/users/"
	case "ORGS":
		toReturn = apiEndpoint + "/orgs/"
	case "USER_INFO":
		toReturn = apiEndpoint + "/user"
	case "ORG_INFO":
		toReturn = apiEndpoint + "/user/orgs?per_page=1"
	case "USER_PICTURE":
		toReturn = "https://avatars.fiwareusercontent.com/u/" + endpoint + "?v=3&s=72"
	case "USER_SEARCH":
		toReturn = apiEndpoint + "/search/users?q="
	case "TEAM":
		toReturn = apiEndpoint + "/teams/"
	case "TEAMS":
		toReturn = apiEndpoint + "/user/teams?per_page=100"
	case "TEAM_PROFILE":
		toReturn = hostName + "/orgs/%s/teams/%s"
	default:
		toReturn = apiEndpoint
	}

	return toReturn
}
