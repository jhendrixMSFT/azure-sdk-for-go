// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package armcore

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// RegistrationOptions configures the registration policy's behavior.
type RegistrationOptions struct {
	// DisableAutoRegistration will skip automatic registration of a resource provider.
	// The default value is false.
	DisableAutoRegistration bool
}

// DefaultRegistrationOptions returns an instance of RegistrationOptions initialized with default values.
func DefaultRegistrationOptions() RegistrationOptions {
	return RegistrationOptions{}
}

// NewRPRegistrationPolicy creates a policy object configured using the specified pipeline
// and options. Pass nil to accept the default options; this is the same as passing the result
// from a call to DefaultRegistrationOptions().
func NewRPRegistrationPolicy(p azcore.Pipeline, o *RegistrationOptions) azcore.Policy {
	if o == nil {
		def := DefaultRegistrationOptions()
		o = &def
	}
	return &rpRegistrationPolicy{pipeline: p, options: *o}
}

type rpRegistrationPolicy struct {
	pipeline azcore.Pipeline
	options  RegistrationOptions
}

func (r *rpRegistrationPolicy) Do(ctx context.Context, req *azcore.Request) (*azcore.Response, error) {
	const unregisteredRPCode = "MissingSubscriptionRegistration"
	const registeredState = "Registered"
	// TODO: cap
	for {
		resp, err := req.Next(ctx)
		// getting a 409 is the first indication that the RP might need to be registered, check error response
		if err != nil || resp.StatusCode != http.StatusConflict || r.options.DisableAutoRegistration {
			return resp, err
		}
		var reqErr requestError
		if err = resp.UnmarshalAsJSON(&reqErr); err != nil {
			// TODO: stack trace
			return resp, err
		}
		if reqErr.ServiceError == nil {
			// TODO: stack trace
			return resp, errors.New("unexpected nil error")
		}
		if reqErr.ServiceError.Code != unregisteredRPCode {
			// not a 409 due to unregistered RP
			return resp, err
		}
		// RP needs to be registered.  start by getting the subscription ID from the original request
		subID, err := getSubscription(req.URL.Path)
		if err != nil {
			// TODO: stack trace
			return resp, err
		}
		// now get the RP from the error
		rp, err := getProvider(reqErr)
		if err != nil {
			// TODO: stack trace
			return resp, err
		}
		// create client and make the registration request
		rpOps := &providersOperations{
			p:     r.pipeline,
			u:     req.URL,
			subID: subID,
		}
		_, err = rpOps.Register(ctx, rp)
		if err != nil {
			// TODO: should we return the response from Register?  both responses (how)?
			// TODO: stack trace
			return resp, err
		}
		// RP was registered, however we need to wait for the registration to complete
		// TODO: cap
		for {
			getResp, err := rpOps.Get(ctx, rp)
			if err != nil {
				// TODO: should we return the response from Register?  both responses (how)?
				// TODO: stack trace
				return resp, err
			}
			if getResp.Provider.RegistrationState != nil && *getResp.Provider.RegistrationState == registeredState {
				// registration complete
				break
			}
			// TODO: sleep
		}
		// RP was successfully registered, retry the original request
		err = req.RewindBody()
		if err != nil {
			// TODO: stack trace
			return resp, err
		}
	}
}

func getSubscription(path string) (string, error) {
	parts := strings.Split(path, "/")
	for i, v := range parts {
		if v == "subscriptions" && (i+1) < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("failed to obtain subscription ID from %s", path)
}

func getProvider(re requestError) (string, error) {
	if len(re.ServiceError.Details) > 0 {
		return re.ServiceError.Details[0].Target, nil
	}
	return "", errors.New("provider was not found in the response")
}

// minimal error definitions to simplify detection
type requestError struct {
	ServiceError *serviceError `json:"error`
}

type serviceError struct {
	Code    string                `json:"code"`
	Details []serviceErrorDetails `json:"details"`
}

type serviceErrorDetails struct {
	Code   string `json:"code"`
	Target string `json:"target"`
}

// the following code was copied from module armresources, providers.go and models.go
// only the minimum amount of code was copied to get this working and some edits were made.

type providersOperations struct {
	p     azcore.Pipeline
	u     *url.URL
	subID string
}

// Get - Gets the specified resource provider.
func (client *providersOperations) Get(ctx context.Context, resourceProviderNamespace string) (*ProviderResponse, error) {
	req, err := client.getCreateRequest(resourceProviderNamespace)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.getHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// getCreateRequest creates the Get request.
func (client *providersOperations) getCreateRequest(resourceProviderNamespace string) (*azcore.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}"
	urlPath = strings.ReplaceAll(urlPath, "{resourceProviderNamespace}", url.PathEscape(resourceProviderNamespace))
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subID))
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2019-05-01")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodGet, *u)
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *providersOperations) getHandleResponse(resp *azcore.Response) (*ProviderResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.getHandleError(resp)
	}
	result := ProviderResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.Provider)
}

// getHandleError handles the Get error response.
func (client *providersOperations) getHandleError(resp *azcore.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s; failed to read response body: %w", resp.Status, err)
	}
	if len(body) == 0 {
		return errors.New(resp.Status)
	}
	return errors.New(string(body))
}

// Register - Registers a subscription with a resource provider.
func (client *providersOperations) Register(ctx context.Context, resourceProviderNamespace string) (*ProviderResponse, error) {
	req, err := client.registerCreateRequest(resourceProviderNamespace)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.registerHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// registerCreateRequest creates the Register request.
func (client *providersOperations) registerCreateRequest(resourceProviderNamespace string) (*azcore.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}/register"
	urlPath = strings.ReplaceAll(urlPath, "{resourceProviderNamespace}", url.PathEscape(resourceProviderNamespace))
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subID))
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2019-05-01")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodPost, *u)
	return req, nil
}

// registerHandleResponse handles the Register response.
func (client *providersOperations) registerHandleResponse(resp *azcore.Response) (*ProviderResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.registerHandleError(resp)
	}
	result := ProviderResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.Provider)
}

// registerHandleError handles the Register error response.
func (client *providersOperations) registerHandleError(resp *azcore.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s; failed to read response body: %w", resp.Status, err)
	}
	if len(body) == 0 {
		return errors.New(resp.Status)
	}
	return errors.New(string(body))
}

// ProviderResponse is the response envelope for operations that return a Provider type.
type ProviderResponse struct {
	// Resource provider information.
	Provider *Provider

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// Resource provider information.
type Provider struct {
	// The provider ID.
	ID *string `json:"id,omitempty"`

	// The namespace of the resource provider.
	Namespace *string `json:"namespace,omitempty"`

	// The registration policy of the resource provider.
	RegistrationPolicy *string `json:"registrationPolicy,omitempty"`

	// The registration state of the resource provider.
	RegistrationState *string `json:"registrationState,omitempty"`
}
