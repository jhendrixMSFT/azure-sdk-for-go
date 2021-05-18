// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	deviceCode                   = "device_code"
	deviceCodeResponse           = `{"user_code":"test_code","device_code":"test_device_code","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5,"message":"To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code test_code to authenticate."}`
	deviceCodeScopes             = "user.read offline_access openid profile email"
	authorizationPendingResponse = `{"error": "authorization_pending","error_description": "Authorization pending.","error_codes": [],"timestamp": "2019-12-01 19:00:00Z","trace_id": "2d091b0","correlation_id": "a999","error_uri": "https://login.contoso.com/error?code=0"}`
	expiredTokenResponse         = `{"error": "expired_token","error_description": "Token has expired.","error_codes": [],"timestamp": "2019-12-01 19:00:00Z","trace_id": "2d091b0","correlation_id": "a999","error_uri": "https://login.contoso.com/error?code=0"}`
)

func TestDeviceCodeCredential_InvalidTenantID(t *testing.T) {
	options := DeviceCodeCredentialOptions{}
	options.TenantID = badTenantID
	cred, err := NewDeviceCodeCredential(&options)
	if err == nil {
		t.Fatal("Expected an error but received none")
	}
	if cred != nil {
		t.Fatalf("Expected a nil credential value. Received: %v", cred)
	}
	var errType CredentialUnavailableError
	if !errors.As(err, &errType) {
		t.Fatalf("Did not receive a CredentialUnavailableError. Received: %t", err)
	}
}

func TestDeviceCodeCredential_GetTokenSuccess(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		ar: public.AuthResult{
			AccessToken: tokenValue,
		},
		dc: public.DeviceCode{
			Result: public.DeviceCodeResult{},
		},
	}
	tk, err := cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
	if tk.Token != tokenValue {
		t.Fatalf("Received an unexpected value in azcore.AccessToken.Token")
	}
}

func TestDeviceCodeCredential_GetTokenInvalidCredentials(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		err: errors.New("invalid credentials"),
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one.")
	}
	var authFailed AuthenticationFailedError
	if !errors.As(err, &authFailed) {
		t.Fatalf("Expected: AuthenticationFailedError, Received: %T", err)
	}
}

func TestDeviceCodeCredential_GetTokenAuthorizationPending(t *testing.T) {
	cred, err := NewDeviceCodeCredential(&DeviceCodeCredentialOptions{
		UserPrompt: func(DeviceCodeMessage) {},
	})
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err != nil {
		t.Fatalf("Expected an empty error but received %v", err)
	}
}

func TestDeviceCodeCredential_GetTokenExpiredToken(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err == nil {
		t.Fatalf("Expected an error but received none")
	}
	var authFailed AuthenticationFailedError
	if !errors.As(err, &authFailed) {
		t.Fatalf("Expected: AuthenticationFailedError, Received: %T", err)
	}
}

func TestDeviceCodeCredential_GetTokenWithRefreshTokenFailure(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	// TODO: cred.refreshToken = "refresh_token"
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one")
	}
	var aadErr AuthenticationFailedError
	if !errors.As(err, &aadErr) {
		t.Fatalf("Did not receive an AADAuthenticationFailedError but was expecting one")
	}
}

func TestDeviceCodeCredential_GetTokenWithRefreshTokenSuccess(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	// TODO: cred.refreshToken = "refresh_token"
	tk, err := cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err != nil {
		t.Fatalf("Received an unexpected error: %s", err.Error())
	}
	if tk.Token != tokenValue {
		t.Fatalf("Unexpected value for token")
	}
}

func TestBearerPolicy_DeviceCodeCredential(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(deviceCodeResponse)))
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespSuccess)))
	srv.AppendResponse(mock.WithStatusCode(http.StatusOK))
	options := DeviceCodeCredentialOptions{}
	options.ClientID = clientID
	options.TenantID = tenantID
	options.HTTPClient = srv
	options.AuthorityHost = srv.URL()
	options.UserPrompt = func(DeviceCodeMessage) {}
	cred, err := NewDeviceCodeCredential(&options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	pipeline := defaultTestPipeline(srv, cred, deviceCodeScopes)
	req, err := azcore.NewRequest(context.Background(), http.MethodGet, srv.URL())
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipeline.Do(req)
	if err != nil {
		t.Fatalf("Expected an empty error but receive: %v", err)
	}
}
