package policy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Credential represent any credential type; it is used to create a credential policy Factory.
type Credential interface {
	pipeline.Factory
	credentialMarker()
}

// NewServicePrincipal creates a new bearer authorizor.
func NewServicePrincipal(tenentID, clientID, clientSecret string) (sp ServicePrincipal, err error) {
	oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenentID)
	if err != nil {
		return
	}
	sp.spt, err = adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, azure.PublicCloud.ResourceManagerEndpoint)
	return
}

// ServicePrincipal represents credentials created from a service principal.
type ServicePrincipal struct {
	spt *adal.ServicePrincipalToken
}

func (ServicePrincipal) credentialMarker() {}

// New creates a credential policy object from the associated ServicePrincipal.
func (ba ServicePrincipal) New(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.Policy {
	return pipeline.PolicyFunc(func(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
		err := ba.spt.EnsureFreshWithContext(ctx)
		if err != nil {
			return nil, err
		}
		if request.Header == nil {
			request.Header = make(http.Header)
		}
		request.Header.Set(http.CanonicalHeaderKey("Authorization"), fmt.Sprintf("Bearer %s", ba.spt.OAuthToken()))
		return next.Do(ctx, request)
	})
}
