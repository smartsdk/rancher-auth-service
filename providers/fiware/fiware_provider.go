package fiware

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"net/http"
)

//Constants for fiware
const (
	Name                           = "fiware"
	Config                         = Name + "config"
	TokenType                      = Name + "jwt"
	UserType                       = Name + "_user"
	OrgType                        = Name + "_org"
	TeamType                       = Name + "_team"
	hostnameSetting                = "api.fiware.domain"
	schemeSetting                  = "api.fiware.scheme"
	clientIDSetting                = "api.auth.fiware.client.id"
	clientSecretSetting            = "api.auth.fiware.client.secret"
	redirectURISetting             = "api.auth.fiware.redirectURI"
	fiwareAccessModeSetting        = "api.auth.fiware.access.mode"
	fiwareAllowedIdentitiesSetting = "api.auth.fiware.allowed.identities"
)

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() *GProvider {
	client := &http.Client{}
	fiwareClient := &FClient{}
	fiwareClient.httpClient = client

	fiwareProvider := &GProvider{}
	fiwareProvider.fiwareClient = fiwareClient

	return fiwareProvider
}

//GProvider implements an IdentityProvider for fiware
type GProvider struct {
	fiwareClient *FClient
}

//GetName returns the name of the provider
func (g *GProvider) GetName() string {
	return Name
}

//GetUserType returns the string used to identify a user account for this provider
func (g *GProvider) GetUserType() string {
	return UserType
}

//GenerateToken authenticates the given code and returns the token
func (g *GProvider) GenerateToken(json map[string]string) (model.Token, error) {
	//getAccessToken
	securityCode := json["code"]
	accessToken := json["accessToken"]

	if securityCode != "" {
		log.Debugf("GitHubIdentityProvider GenerateToken called for securityCode %v", securityCode)
		accessToken, err := g.fiwareClient.getAccessToken(securityCode)
		if err != nil {
			log.Errorf("Error with %v", securityCode)
			log.Errorf("Error generating accessToken from fiware %v", err)
			return model.Token{}, err
		}
		log.Debugf("Received AccessToken from fiware %v", accessToken)
		return g.createToken(accessToken)
	} else if accessToken != "" {
		return g.createToken(accessToken)
	} else {
		return model.Token{}, fmt.Errorf("Cannot gerenate token from fiware, invalid request data")
	}
}

func (g *GProvider) createToken(accessToken string) (model.Token, error) {
	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.AccessToken = accessToken
	//getIdentities from accessToken
	identities, err := g.GetIdentities(accessToken)
	if err != nil {
		log.Errorf("Error getting identities using accessToken from fiware %v", err)
		return model.Token{}, err
	}
	token.IdentityList = identities
	token.Type = TokenType
	user, ok := GetUserIdentity(identities, UserType)
	if !ok {
		log.Error("User identity not found using accessToken from fiware")
		return model.Token{}, fmt.Errorf("User identity not found using accessToken from fiware")
	}
	token.ExternalAccountID = user.ExternalId
	return token, nil
}

//GetUserIdentity returns the "user" from the list of identities
func GetUserIdentity(identities []client.Identity, userType string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType {
			return identity, true
		}
	}
	return client.Identity{}, false
}

//RefreshToken re-authenticates and generate a new token
func (g *GProvider) RefreshToken(json map[string]string) (model.Token, error) {
	accessToken := json["accessToken"]
	if accessToken != "" {
		log.Debugf("GitHubIdentityProvider RefreshToken called for accessToken %v", accessToken)
		return g.createToken(accessToken)
	}
	return model.Token{}, fmt.Errorf("Cannot refresh token from fiware, no access token found in request")
}

//GetIdentities returns list of user and group identities associated to this token
func (g *GProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.fiwareClient.getFiwareUser(accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)
		identities = append(identities, userIdentity)
	}
	/*
	orgAccts, err := g.fiwareClient.getFiwareOrgs(accessToken)
	if err == nil {
		for _, orgAcct := range orgAccts {
			orgIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			orgAcct.toIdentity(OrgType, &orgIdentity)
			identities = append(identities, orgIdentity)
		}
	}
	teamAccts, err := g.fiwareClient.getFiwareTeams(accessToken)
	if err == nil {
		for _, teamAcct := range teamAccts {
			teamIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			teamAcct.toIdentity(TeamType, &teamIdentity)
			identities = append(identities, teamIdentity)
		}
	}
	*/

	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (g *GProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	identity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}

	switch externalIDType {
	case UserType:
		fallthrough
	case OrgType:
		fiwareAcct, err := g.fiwareClient.getUserOrgByID(externalID, accessToken)
		if err != nil {
			return identity, err
		}
		fiwareAcct.toIdentity(externalIDType, &identity)
		return identity, nil
	case TeamType:
		fiwareAcct, err := g.fiwareClient.getUserOrgByID(externalID, accessToken)
		if err != nil {
			return identity, err
		}
		fiwareAcct.toIdentity(externalIDType, &identity)
		return identity, nil
	default:
		log.Debugf("Cannot get the fiware account due to invalid externalIDType %v", externalIDType)
		return identity, fmt.Errorf("Cannot get the fiware account due to invalid externalIDType %v", externalIDType)
	}
}

//SearchIdentities returns the identity by name
func (g *GProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.fiwareClient.getFiwareUserByName(name, accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)

		identities = append(identities, userIdentity)
	}
	/*
	orgAcct, err := g.fiwareClient.getFiwareOrgByName(name, accessToken)
	if err == nil {
		orgIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		orgAcct.toIdentity(OrgType, &orgIdentity)

		identities = append(identities, orgIdentity)
	}
	*/

	return identities, nil
}

//LoadConfig initializes the provider with the passes config
func (g *GProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.FiwareConfig
	g.fiwareClient.config = &configObj
	return nil
}

//GetConfig returns the provider config
func (g *GProvider) GetConfig() model.AuthConfig {
	log.Debug("In fiware getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.FiwareConfig = *g.fiwareClient.config

	authConfig.FiwareConfig.Resource = client.Resource{
		Type: "fiwareconfig",
	}

	log.Debug("In fiware authConfig %v", authConfig)
	return authConfig
}

//GetSettings transforms the provider config to db settings
func (g *GProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[hostnameSetting] = g.fiwareClient.config.Hostname
	settings[schemeSetting] = g.fiwareClient.config.Scheme
	settings[clientIDSetting] = g.fiwareClient.config.ClientID
	if g.fiwareClient.config.ClientSecret != "" {
		settings[clientSecretSetting] = g.fiwareClient.config.ClientSecret
	}
	settings[redirectURISetting] = g.fiwareClient.config.RedirectURI
	return settings
}

//GetProviderSettingList returns the provider specific db setting list
func (g *GProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string
	settings = append(settings, hostnameSetting)
	settings = append(settings, schemeSetting)
	settings = append(settings, clientIDSetting)
	if !listOnly {
		settings = append(settings, clientSecretSetting)
	}
	settings = append(settings, redirectURISetting)
	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (g *GProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	fiwareConfig := model.FiwareConfig{Resource: client.Resource{
		Type: "fiwareconfig",
	}}
	fiwareConfig.Hostname = providerSettings[hostnameSetting]
	fiwareConfig.Scheme = providerSettings[schemeSetting]
	fiwareConfig.ClientID = providerSettings[clientIDSetting]
	fiwareConfig.ClientSecret = providerSettings[clientSecretSetting]
	fiwareConfig.RedirectURI = providerSettings[redirectURISetting]

	authConfig.FiwareConfig = fiwareConfig
}

//GetLegacySettings returns the provider specific legacy db settings
func (g *GProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = fiwareAccessModeSetting
	settings["allowedIdentitiesSetting"] = fiwareAllowedIdentitiesSetting
	return settings
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (g *GProvider) GetRedirectURL() string {
	redirect := ""
	if g.fiwareClient.config.Hostname != "" {
		//redirect = g.fiwareClient.config.Scheme + g.fiwareClient.config.Hostname
		redirect = fiwareDefaultHostName
	} else {
		redirect = fiwareDefaultHostName
	}
	redirect = redirect + "/oauth2/authorize?response_type=code&client_id=" + g.fiwareClient.config.ClientID + "&redirect_uri=" + g.fiwareClient.config.Scheme + g.fiwareClient.config.Hostname

	return redirect
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (g *GProvider) GetIdentitySeparator() string {
	return ","
}
