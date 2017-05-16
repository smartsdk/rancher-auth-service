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
	redirectURISetting             = "api.auth.fiware.redirecturi"
	fiwareAccessModeSetting        = "api.auth.fiware.access.mode"
	fiwareAllowedIdentitiesSetting = "api.auth.fiware.allowed.identities"
)

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() *FProvider {
	client := &http.Client{}
	fiwareClient := &FClient{}
	fiwareClient.httpClient = client

	fiwareProvider := &FProvider{}
	fiwareProvider.fiwareClient = fiwareClient

	return fiwareProvider
}

//FProvider implements an IdentityProvider for fiware
type FProvider struct {
	fiwareClient *FClient
}

//GetName returns the name of the provider
func (g *FProvider) GetName() string {
	return Name
}

//GetUserType returns the string used to identify a user account for this provider
func (g *FProvider) GetUserType() string {
	return UserType
}

//GenerateToken authenticates the given code and returns the token
func (g *FProvider) GenerateToken(json map[string]string) (model.Token, error) {
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

func (g *FProvider) createToken(accessToken string) (model.Token, error) {
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
func (g *FProvider) RefreshToken(json map[string]string) (model.Token, error) {
	accessToken := json["accessToken"]
	if accessToken != "" {
		log.Debugf("GitHubIdentityProvider RefreshToken called for accessToken %v", accessToken)
		return g.createToken(accessToken)
	}
	return model.Token{}, fmt.Errorf("Cannot refresh token from fiware, no access token found in request")
}

//GetIdentities returns list of user and group identities associated to this token
func (g *FProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.fiwareClient.getFiwareUser(accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)
		identities = append(identities, userIdentity)
		for _, org := range userAcct.Organizations {
			orgIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			org.toIdentity(OrgType, &orgIdentity)
			identities = append(identities, orgIdentity)
		}
	}

	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (g *FProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
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
	default:
		log.Debugf("Cannot get the fiware account due to invalid externalIDType %v", externalIDType)
		return identity, fmt.Errorf("Cannot get the fiware account due to invalid externalIDType %v", externalIDType)
	}
}

//SearchIdentities returns the identity by name
func (g *FProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.fiwareClient.getFiwareUserByName(name, accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)

		identities = append(identities, userIdentity)
	}

	return identities, nil
}

//LoadConfig initializes the provider with the passes config
func (g *FProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.FiwareConfig
	g.fiwareClient.config = &configObj
	return nil
}

//GetConfig returns the provider config
func (g *FProvider) GetConfig() model.AuthConfig {
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
func (g *FProvider) GetSettings() map[string]string {
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
func (g *FProvider) GetProviderSettingList(listOnly bool) []string {
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
func (g *FProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
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
func (g *FProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = fiwareAccessModeSetting
	settings["allowedIdentitiesSetting"] = fiwareAllowedIdentitiesSetting
	return settings
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (g *FProvider) GetRedirectURL() string {
	redirect := ""
	if g.fiwareClient.config.Hostname != "" {
		//redirect = g.fiwareClient.config.Scheme + g.fiwareClient.config.Hostname
		redirect = fiwareDefaultHostName
	} else {
		redirect = fiwareDefaultHostName
	}
	//redirect = redirect + "/oauth2/authorize?response_type=code&client_id=" + g.fiwareClient.config.ClientID + "&redirect_uri=" + g.fiwareClient.config.RedirectURI
	redirect = redirect + "/oauth2/authorize?response_type=code&client_id=" + g.fiwareClient.config.ClientID

	return redirect
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (g *FProvider) GetIdentitySeparator() string {
	return ","
}
