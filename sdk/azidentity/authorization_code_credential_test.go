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
)

const (
	testAuthCode    = "12345"
	testRedirectURI = "http://localhost"
)

func TestAuthorizationCodeCredential_InvalidTenantID(t *testing.T) {
	cred, err := NewAuthorizationCodeCredential(badTenantID, clientID, testAuthCode, testRedirectURI, nil)
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

func TestAuthorizationCodeCredential_GetTokenSuccess(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespSuccess)))
	options := AuthorizationCodeCredentialOptions{}
	options.ClientSecret = secret
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewAuthorizationCodeCredential(tenantID, clientID, testAuthCode, testRedirectURI, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %v", err)
	}
}

func TestAuthorizationCodeCredential_GetTokenInvalidCredentials(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.SetResponse(mock.WithBody([]byte(accessTokenRespError)), mock.WithStatusCode(http.StatusUnauthorized))
	options := AuthorizationCodeCredentialOptions{}
	options.ClientSecret = secret
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewAuthorizationCodeCredential(tenantID, clientID, testAuthCode, testRedirectURI, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one.")
	}
	var authFailed AuthenticationFailedError
	if !errors.As(err, &authFailed) {
		t.Fatalf("Expected: AuthenticationFailedError, Received: %T", err)
	}
}

func TestAuthorizationCodeCredential_GetTokenUnexpectedJSON(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespMalformed)))
	options := AuthorizationCodeCredentialOptions{}
	options.ClientSecret = secret
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewAuthorizationCodeCredential(tenantID, clientID, testAuthCode, testRedirectURI, &options)
	if err != nil {
		t.Fatalf("Failed to create the credential")
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatalf("Expected a JSON marshal error but received nil")
	}
}
