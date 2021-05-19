// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// DeviceCodeCredentialOptions provide options that can configure DeviceCodeCredential instead of using the default values.
// All zero-value fields will be initialized with their default values. Please note, that both the TenantID or ClientID fields should
// changed together if default values are not desired.
type DeviceCodeCredentialOptions struct {
	// Gets the Azure Active Directory tenant (directory) ID of the service principal
	// The default value is "organizations". If this value is changed, then also change ClientID to the corresponding value.
	TenantID string
	// Gets the client (application) ID of the service principal
	// The default value is the developer sign on ID for the corresponding "organizations" TenantID.
	ClientID string
	// The callback function used to send the login message back to the user
	// The default will print device code log in information to stdout.
	UserPrompt func(DeviceCodeMessage)
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

// init provides the default settings for DeviceCodeCredential.
// It will set the following default values:
// TenantID set to "organizations".
// ClientID set to the default developer sign on client ID "04b07795-8ddb-461a-bbee-02f9e1bf7b46".
// UserPrompt set to output login information for the user to stdout.
func (o *DeviceCodeCredentialOptions) init() {
	if o.TenantID == "" {
		o.TenantID = organizationsTenantID
	}
	if o.ClientID == "" {
		o.ClientID = developerSignOnClientID
	}
	if o.UserPrompt == nil {
		o.UserPrompt = func(dc DeviceCodeMessage) {
			fmt.Println(dc.Message)
		}
	}
}

// DeviceCodeMessage is used to store device code related information to help the user login and allow the device code flow to continue
// to request a token to authenticate a user.
type DeviceCodeMessage struct {
	// User code returned by the service.
	UserCode string `json:"user_code"`
	// Verification URL where the user must navigate to authenticate using the device code and credentials.
	VerificationURL string `json:"verification_uri"`
	// User friendly text response that can be used for display purposes.
	Message string `json:"message"`
}

// DeviceCodeCredential authenticates a user using the device code flow, and provides access tokens for that user account.
// For more information on the device code authentication flow see: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code.
type DeviceCodeCredential struct {
	client     publicClient
	userPrompt func(DeviceCodeMessage) // Sends the user a message with a verification URL and device code to sign in to the login server
}

// NewDeviceCodeCredential constructs a new DeviceCodeCredential used to authenticate against Azure Active Directory with a device code.
// options: Options used to configure the management of the requests sent to Azure Active Directory, please see DeviceCodeCredentialOptions for a description of each field.
func NewDeviceCodeCredential(options *DeviceCodeCredentialOptions) (*DeviceCodeCredential, error) {
	cp := DeviceCodeCredentialOptions{}
	if options != nil {
		cp = *options
	}
	cp.init()
	if !validTenantID(cp.TenantID) {
		return nil, newCredentialUnavailableError("Device Code Credential", tenantIDValidationErr)
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
	return &DeviceCodeCredential{userPrompt: cp.UserPrompt, client: c}, nil
}

// GetToken obtains a token from Azure Active Directory, following the device code authentication
// flow. This function first requests a device code and requests that the user login before continuing to authenticate the device.
// This function will keep polling the service for a token until the user logs in.
// scopes: The list of scopes for which the token will have access. The "offline_access" scope is checked for and automatically added in case it isn't present to allow for silent token refresh.
// ctx: The context for controlling the request lifetime.
// Returns an AccessToken which can be used to authenticate service client calls.
func (c *DeviceCodeCredential) GetToken(ctx context.Context, opts azcore.TokenRequestOptions) (*azcore.AccessToken, error) {
	// check for cached token
	tk, err := c.client.AcquireTokenSilent(ctx, opts.Scopes)
	if err == nil {
		return &azcore.AccessToken{
			Token:     tk.AccessToken,
			ExpiresOn: tk.ExpiresOn,
		}, err
	}
	dc, err := c.client.AcquireTokenByDeviceCode(ctx, opts.Scopes)
	if err != nil {
		addGetTokenFailureLogs("Device Code Credential", err, true)
		return nil, newAuthenticationFailedError(err)
	}
	c.userPrompt(DeviceCodeMessage{
		UserCode:        dc.Result.UserCode,
		VerificationURL: dc.Result.VerificationURL,
		Message:         dc.Result.Message,
	})
	tk, err = dc.AuthenticationResult(ctx)
	if err != nil {
		addGetTokenFailureLogs("Device Code Credential", err, true)
		return nil, newAuthenticationFailedError(err)
	}
	logGetTokenSuccess(c, opts)
	return &azcore.AccessToken{
		Token:     tk.AccessToken,
		ExpiresOn: tk.ExpiresOn,
	}, err
}

// AuthenticationPolicy implements the azcore.Credential interface on DeviceCodeCredential.
func (c *DeviceCodeCredential) AuthenticationPolicy(options azcore.AuthenticationPolicyOptions) azcore.Policy {
	return newBearerTokenPolicy(c, options)
}

// deviceCodeResult is used to store device code related information to help the user login and allow the device code flow to continue
// to request a token to authenticate a user
type deviceCodeResult struct {
	UserCode        string `json:"user_code"`        // User code returned by the service.
	DeviceCode      string `json:"device_code"`      // Device code returned by the service.
	VerificationURL string `json:"verification_uri"` // Verification URL where the user must navigate to authenticate using the device code and credentials.
	Interval        int64  `json:"interval"`         // Polling interval time to check for completion of authentication flow.
	Message         string `json:"message"`          // User friendly text response that can be used for display purposes.
}

var _ azcore.TokenCredential = (*DeviceCodeCredential)(nil)
