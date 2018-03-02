package model

import "github.com/rancher/go-rancher/client"

//FiwareConfig stores the fiware config read from JSON file
type FiwareConfig struct {
	client.Resource
	Hostname     string `json:"hostname"`
	Scheme       string `json:"scheme"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirecturi"`
}
