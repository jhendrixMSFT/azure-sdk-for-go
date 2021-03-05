// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// ClientSecretCredentialOptions configures the ClientSecretCredential with optional parameters.
// All zero-value fields will be initialized with their default values.
type ClientSecretCredentialOptions struct {
	// The host of the Azure Active Directory authority. The default is AzurePublicCloud.
	// Leave empty to allow overriding the value from the AZURE_AUTHORITY_HOST environment variable.
	AuthorityHost string
	// HTTPClient sets the transport for making HTTP requests
	// Leave this as nil to use the default HTTP transport
	HTTPClient azcore.Transport
	// Retry configures the built-in retry policy behavior
	Retry azcore.RetryOptions
	// Telemetry configures the built-in telemetry policy behavior
	Telemetry azcore.TelemetryOptions
	// Logging configures the built-in logging policy behavior.
	Logging azcore.LogOptions
}

// ClientSecretCredential enables authentication to Azure Active Directory using a client secret that was generated for an App Registration.  More information on how
// to configure a client secret can be found here:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis#add-credentials-to-your-web-application
type ClientSecretCredential struct {
	client confidential.Client
}

// NewClientSecretCredential constructs a new ClientSecretCredential with the details needed to authenticate against Azure Active Directory with a client secret.
// tenantID: The Azure Active Directory tenant (directory) ID of the service principal.
// clientID: The client (application) ID of the service principal.
// clientSecret: A client secret that was generated for the App Registration used to authenticate the client.
// options: allow to configure the management of the requests sent to Azure Active Directory.
func NewClientSecretCredential(tenantID string, clientID string, clientSecret string, options *ClientSecretCredentialOptions) (*ClientSecretCredential, error) {
	if !validTenantID(tenantID) {
		return nil, &CredentialUnavailableError{credentialType: "Client Secret Credential", message: tenantIDValidationErr}
	}
	if options == nil {
		options = &ClientSecretCredentialOptions{}
	}
	authorityHost, err := setAuthorityHost(options.AuthorityHost)
	if err != nil {
		return nil, err
	}
	//pipeline := newDefaultPipeline(pipelineOptions{HTTPClient: options.HTTPClient, Retry: options.Retry, Telemetry: options.Telemetry, Logging: options.Logging})
	cred, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return nil, err
	}
	c, err := confidential.New(clientID, cred,
		confidential.WithAuthority(azcore.JoinPaths(authorityHost, tenantID)),
		/*confidential.WithHTTPClient(pipelineAdapter{pl: pipeline})*/)
	if err != nil {
		return nil, err
	}
	return &ClientSecretCredential{client: c}, nil
}

// GetToken obtains a token from Azure Active Directory, using the specified client secret to authenticate.
// ctx: Context used to control the request lifetime.
// opts: TokenRequestOptions contains the list of scopes for which the token will have access.
// Returns an AccessToken which can be used to authenticate service client calls.
func (c *ClientSecretCredential) GetToken(ctx context.Context, opts azcore.TokenRequestOptions) (*azcore.AccessToken, error) {
	// check for cached token
	tk, err := c.client.AcquireTokenSilent(ctx, opts.Scopes)
	if err == nil {
		return &azcore.AccessToken{
			Token:     tk.AccessToken,
			ExpiresOn: tk.ExpiresOn,
		}, err
	}
	// request token
	tk, err = c.client.AcquireTokenByCredential(ctx, opts.Scopes)
	if err != nil {
		addGetTokenFailureLogs("Client Secret Credential", err, true)
		return nil, err
	}
	logGetTokenSuccess(c, opts)
	return &azcore.AccessToken{
		Token:     tk.AccessToken,
		ExpiresOn: tk.ExpiresOn,
	}, err
}

// AuthenticationPolicy implements the azcore.Credential interface on ClientSecretCredential and calls the Bearer Token policy
// to get the bearer token.
func (c *ClientSecretCredential) AuthenticationPolicy(options azcore.AuthenticationPolicyOptions) azcore.Policy {
	return newBearerTokenPolicy(c, options)
}

var _ azcore.TokenCredential = (*ClientSecretCredential)(nil)
