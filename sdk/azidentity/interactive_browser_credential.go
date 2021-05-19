// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// InteractiveBrowserCredentialOptions can be used when providing additional credential information, such as a client secret.
// Use these options to modify the default pipeline behavior if necessary.
// All zero-value fields will be initialized with their default values. Please note, that both the TenantID or ClientID fields should
// changed together if default values are not desired.
type InteractiveBrowserCredentialOptions struct {
	// The Azure Active Directory tenant (directory) ID of the service principal.
	// The default value is "organizations". If this value is changed, then also change ClientID to the corresponding value.
	TenantID string
	// The client (application) ID of the service principal.
	// The default value is the developer sign on ID for the corresponding "organizations" TenantID.
	ClientID string
	// The client secret that was generated for the App Registration used to authenticate the client. Only applies for web apps.
	ClientSecret string
	// The redirect URL used to request the authorization code. Must be the same URL that is configured for the App Registration.
	RedirectURL string
	// The localhost port for the local server that will be used to redirect back.
	// By default, a random port number will be selected.
	Port int
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

// init returns an instance of InteractiveBrowserCredentialOptions initialized with default values.
func (o *InteractiveBrowserCredentialOptions) init() {
	if o.TenantID == "" {
		o.TenantID = organizationsTenantID
	}
	if o.ClientID == "" {
		o.ClientID = developerSignOnClientID
	}
}

// InteractiveBrowserCredential enables authentication to Azure Active Directory using an interactive browser to log in.
type InteractiveBrowserCredential struct {
	client      publicClient
	port        int
	redirectURL string
}

// NewInteractiveBrowserCredential constructs a new InteractiveBrowserCredential with the details needed to authenticate against Azure Active Directory through an interactive browser window.
// options: configure the management of the requests sent to Azure Active Directory, pass in nil or a zero-value options instance for default behavior.
func NewInteractiveBrowserCredential(options *InteractiveBrowserCredentialOptions) (*InteractiveBrowserCredential, error) {
	cp := InteractiveBrowserCredentialOptions{}
	if options != nil {
		cp = *options
	}
	cp.init()
	if !validTenantID(cp.TenantID) {
		return nil, newCredentialUnavailableError("Interactive Browser Credential", tenantIDValidationErr)
	}
	authorityHost, err := setAuthorityHost(cp.AuthorityHost)
	if err != nil {
		return nil, err
	}
	pipeline := newDefaultPipeline(pipelineOptions{HTTPClient: cp.HTTPClient, Retry: cp.Retry, Telemetry: cp.Telemetry, Logging: cp.Logging})
	c, err := public.New(cp.ClientID,
		public.WithAuthority(azcore.JoinPaths(authorityHost, cp.TenantID)),
		public.WithHTTPClient(pipelineAdapter{pl: pipeline}))
	if err != nil {
		return nil, err
	}
	return &InteractiveBrowserCredential{client: c, port: cp.Port, redirectURL: cp.RedirectURL}, nil
}

// GetToken obtains a token from Azure Active Directory using an interactive browser to authenticate.
// ctx: Context used to control the request lifetime.
// opts: TokenRequestOptions contains the list of scopes for which the token will have access.
// Returns an AccessToken which can be used to authenticate service client calls.
func (c *InteractiveBrowserCredential) GetToken(ctx context.Context, opts azcore.TokenRequestOptions) (*azcore.AccessToken, error) {
	// check for cached token
	tk, err := c.client.AcquireTokenSilent(ctx, opts.Scopes)
	if err == nil {
		return &azcore.AccessToken{
			Token:     tk.AccessToken,
			ExpiresOn: tk.ExpiresOn,
		}, err
	}
	// TODO: wire up custom port number/redirect URL (which is only used for port)
	tk, err = c.client.AcquireTokenInteractive(ctx, opts.Scopes)
	if err != nil {
		addGetTokenFailureLogs("Interactive Browser Credential", err, true)
		return nil, newAuthenticationFailedError(err)
	}
	logGetTokenSuccess(c, opts)
	return &azcore.AccessToken{
		Token:     tk.AccessToken,
		ExpiresOn: tk.ExpiresOn,
	}, err
}

// AuthenticationPolicy implements the azcore.Credential interface on InteractiveBrowserCredential.
func (c *InteractiveBrowserCredential) AuthenticationPolicy(options azcore.AuthenticationPolicyOptions) azcore.Policy {
	return newBearerTokenPolicy(c, options)
}

var _ azcore.TokenCredential = (*InteractiveBrowserCredential)(nil)
