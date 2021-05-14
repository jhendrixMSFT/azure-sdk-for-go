// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	// AzureChina is a global constant to use in order to access the Azure China cloud.
	AzureChina = "https://login.chinacloudapi.cn/"
	// AzureGermany is a global constant to use in order to access the Azure Germany cloud.
	AzureGermany = "https://login.microsoftonline.de/"
	// AzureGovernment is a global constant to use in order to access the Azure Government cloud.
	AzureGovernment = "https://login.microsoftonline.us/"
	// AzurePublicCloud is a global constant to use in order to access the Azure public cloud.
	AzurePublicCloud = "https://login.microsoftonline.com/"
	// defaultSuffix is a suffix the signals that a string is in scope format
	defaultSuffix = "/.default"
)

const tenantIDValidationErr = "Invalid tenantID provided. You can locate your tenantID by following the instructions listed here: https://docs.microsoft.com/partner-center/find-ids-and-domain-names."

var (
	successStatusCodes = [2]int{
		http.StatusOK,      // 200
		http.StatusCreated, // 201
	}
)

type tokenResponse struct {
	token        *azcore.AccessToken
	refreshToken string
}

// pipelineOptions are used to configure how requests are made to Azure Active Directory.
type pipelineOptions struct {
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

// setAuthorityHost initializes the authority host for credentials.
func setAuthorityHost(authorityHost string) (string, error) {
	if authorityHost == "" {
		authorityHost = AzurePublicCloud
		// NOTE: we only allow overriding the authority host if no host was specified
		if envAuthorityHost := os.Getenv("AZURE_AUTHORITY_HOST"); envAuthorityHost != "" {
			authorityHost = envAuthorityHost
		}
	}
	u, err := url.Parse(authorityHost)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.New("cannot use an authority host without https")
	}
	return authorityHost, nil
}

// newDefaultPipeline creates a pipeline using the specified pipeline options.
func newDefaultPipeline(o pipelineOptions) azcore.Pipeline {
	return azcore.NewPipeline(
		o.HTTPClient,
		azcore.NewTelemetryPolicy(&o.Telemetry),
		azcore.NewRetryPolicy(&o.Retry),
		azcore.NewLogPolicy(&o.Logging))
}

// newDefaultMSIPipeline creates a pipeline using the specified pipeline options needed
// for a Managed Identity, such as a MSI specific retry policy.
func newDefaultMSIPipeline(o ManagedIdentityCredentialOptions) azcore.Pipeline {
	var statusCodes []int
	// retry policy for MSI is not end-user configurable
	retryOpts := azcore.RetryOptions{
		MaxRetries:    5,
		MaxRetryDelay: 1 * time.Minute,
		RetryDelay:    2 * time.Second,
		TryTimeout:    1 * time.Minute,
		StatusCodes: append(statusCodes,
			// The following status codes are a subset of those found in azcore.StatusCodesForRetry, these are the only ones specifically needed for MSI scenarios
			http.StatusRequestTimeout,      // 408
			http.StatusTooManyRequests,     // 429
			http.StatusInternalServerError, // 500
			http.StatusBadGateway,          // 502
			http.StatusGatewayTimeout,      // 504
			http.StatusNotFound,            //404
			http.StatusGone,                //410
			// all remaining 5xx
			http.StatusNotImplemented,                 // 501
			http.StatusHTTPVersionNotSupported,        // 505
			http.StatusVariantAlsoNegotiates,          // 506
			http.StatusInsufficientStorage,            // 507
			http.StatusLoopDetected,                   // 508
			http.StatusNotExtended,                    // 510
			http.StatusNetworkAuthenticationRequired), // 511
	}
	if o.Telemetry.Value == "" {
		o.Telemetry.Value = UserAgent
	} else {
		o.Telemetry.Value += " " + UserAgent
	}
	return azcore.NewPipeline(
		o.HTTPClient,
		azcore.NewTelemetryPolicy(&o.Telemetry),
		azcore.NewRetryPolicy(&retryOpts),
		azcore.NewLogPolicy(&o.Logging))
}

// validTenantID return true is it receives a valid tenantID, returns false otherwise
func validTenantID(tenantID string) bool {
	match, err := regexp.MatchString("^[0-9a-zA-Z-.]+$", tenantID)
	if err != nil {
		return false
	}
	return match
}

type pipelineAdapter struct {
	pl azcore.Pipeline
}

func (p pipelineAdapter) CloseIdleConnections() {
	// do nothing
}

func (p pipelineAdapter) Do(r *http.Request) (*http.Response, error) {
	req, err := azcore.NewRequest(r.Context(), r.Method, r.URL.String())
	if err != nil {
		return nil, err
	}
	if r.Body != nil && r.Body != http.NoBody {
		// create a rewindable body from the existing body as required
		var body azcore.ReadSeekCloser
		if rsc, ok := r.Body.(azcore.ReadSeekCloser); ok {
			body = rsc
		} else {
			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			body = azcore.NopCloser(bytes.NewReader(b))
		}
		req.SetBody(body, r.Header.Get("Content-Type"))
	}
	resp, err := p.pl.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Response, err
}

// enables fakes for test scenarios
type confidentialClient interface {
	AcquireTokenSilent(ctx context.Context, scopes []string, options ...confidential.AcquireTokenSilentOption) (confidential.AuthResult, error)
	AcquireTokenByAuthCode(ctx context.Context, code string, redirectURI string, scopes []string, options ...confidential.AcquireTokenByAuthCodeOption) (confidential.AuthResult, error)
	AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error)
}

// enables fakes for test scenarios
type publicClient interface {
	AcquireTokenSilent(ctx context.Context, scopes []string, options ...public.AcquireTokenSilentOption) (public.AuthResult, error)
	AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username string, password string) (public.AuthResult, error)
	AcquireTokenByDeviceCode(ctx context.Context, scopes []string) (public.DeviceCode, error)
	AcquireTokenByAuthCode(ctx context.Context, code string, redirectURI string, scopes []string, options ...public.AcquireTokenByAuthCodeOption) (public.AuthResult, error)
	AcquireTokenInteractive(ctx context.Context, scopes []string, options ...public.InteractiveAuthOption) (public.AuthResult, error)
}
