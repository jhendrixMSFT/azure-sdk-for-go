// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// UsernamePasswordCredentialOptions can be used to provide additional information to configure the UsernamePasswordCredential.
// Use these options to modify the default pipeline behavior through the TokenCredentialOptions.
// All zero-value fields will be initialized with their default values.
type UsernamePasswordCredentialOptions struct {
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

// UsernamePasswordCredential enables authentication to Azure Active Directory using a user's  username and password. If the user has MFA enabled this
// credential will fail to get a token returning an AuthenticationFailureError. Also, this credential requires a high degree of trust and is not
// recommended outside of prototyping when more secure credentials can be used.
type UsernamePasswordCredential struct {
	client   publicClient
	username string // Gets the user account's user name
	password string // Gets the user account's password
}

// NewUsernamePasswordCredential constructs a new UsernamePasswordCredential with the details needed to authenticate against Azure Active Directory with
// a simple username and password.
// tenantID: The Azure Active Directory tenant (directory) ID of the service principal.
// clientID: The client (application) ID of the service principal.
// username: A user's account username
// password: A user's account password
// options: UsernamePasswordCredentialOptions used to configure the pipeline for the requests sent to Azure Active Directory.
func NewUsernamePasswordCredential(tenantID string, clientID string, username string, password string, options *UsernamePasswordCredentialOptions) (*UsernamePasswordCredential, error) {
	if !validTenantID(tenantID) {
		return nil, newCredentialUnavailableError("Username Password Credential", tenantIDValidationErr)
	}
	if options == nil {
		options = &UsernamePasswordCredentialOptions{}
	}
	authorityHost, err := setAuthorityHost(options.AuthorityHost)
	if err != nil {
		return nil, err
	}
	pipeline := newDefaultPipeline(pipelineOptions{HTTPClient: options.HTTPClient, Retry: options.Retry, Telemetry: options.Telemetry, Logging: options.Logging})
	c, err := public.New(clientID,
		public.WithAuthority(azcore.JoinPaths(authorityHost, tenantID)),
		public.WithHTTPClient(pipelineAdapter{pl: pipeline}))
	if err != nil {
		return nil, err
	}
	return &UsernamePasswordCredential{username: username, password: password, client: c}, nil
}

// GetToken obtains a token from Azure Active Directory using the specified username and password.
// scopes: The list of scopes for which the token will have access.
// ctx: The context used to control the request lifetime.
// Returns an AccessToken which can be used to authenticate service client calls.
func (c *UsernamePasswordCredential) GetToken(ctx context.Context, opts azcore.TokenRequestOptions) (*azcore.AccessToken, error) {
	tk, err := c.client.AcquireTokenByUsernamePassword(ctx, opts.Scopes, c.username, c.password)
	if err != nil {
		addGetTokenFailureLogs("Username Password Credential", err, true)
		return nil, newAuthenticationFailedError(err)
	}
	logGetTokenSuccess(c, opts)
	return &azcore.AccessToken{
		Token:     tk.AccessToken,
		ExpiresOn: tk.ExpiresOn,
	}, err
}

// AuthenticationPolicy implements the azcore.Credential interface on UsernamePasswordCredential.
func (c *UsernamePasswordCredential) AuthenticationPolicy(options azcore.AuthenticationPolicyOptions) azcore.Policy {
	return newBearerTokenPolicy(c, options)
}
