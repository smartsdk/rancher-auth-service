package fiware

import (
	"fmt"
	"github.com/rancher/go-rancher/client"
)

//Account defines properties an account on fiware has
type Account struct {
	ID        string    `json:"id,omitempty"`
	Login     string `json:"login,omitempty"`
	Name      string `json:"displayName,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	HTMLURL   string `json:"html_url,omitempty"`
	Organizations []Org `json:"organizations,omitempty"`
}

type Org struct {
	Name string `json:"name,omitempty"`
}

func (a *Account) toIdentity(externalIDType string, identity *client.Identity) {
	identity.ExternalId = a.ID
	identity.Resource.Id = externalIDType + ":" + a.ID
	identity.ExternalIdType = externalIDType
	if a.Name != "" {
		identity.Name = a.Name
	} else {
		identity.Name = a.Login
	}
	identity.Login = a.Login
	identity.ProfilePicture = a.AvatarURL
	identity.ProfileUrl = a.HTMLURL
}

func (o *Org) toIdentity(externalIDType string, identity *client.Identity) {
	identity.ExternalId = o.Name
	identity.Resource.Id = externalIDType + ":" + o.Name
	identity.ExternalIdType = externalIDType
	if o.Name != "" {
		identity.Name = o.Name
	} else {
		identity.Name = ""
	}
	identity.Login = o.Name
}

//Team defines properties a team on fiware has
type Team struct {
	ID           string                    `json:"id,omitempty"`
	Organization map[string]interface{} `json:"organization,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Slug         string                 `json:"slug,omitempty"`
}

func (t *Team) toFiwareAccount(url string, account *Account) {
	account.ID = t.ID
	account.Name = t.Name
	orgLogin := (t.Organization["login"]).(string)
	account.AvatarURL = t.Organization["avatar_url"].(string)
	account.HTMLURL = fmt.Sprintf(url, orgLogin, t.Slug)
	account.Login = t.Slug
}
