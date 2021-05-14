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

func TestUsernamePasswordCredential_InvalidTenantID(t *testing.T) {
	cred, err := NewUsernamePasswordCredential(badTenantID, clientID, "username", "password", nil)
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

func TestUsernamePasswordCredential_GetTokenSuccess(t *testing.T) {
	options := UsernamePasswordCredentialOptions{}
	cred, err := NewUsernamePasswordCredential(tenantID, clientID, "username", "password", &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
}

func TestUsernamePasswordCredential_GetTokenInvalidCredentials(t *testing.T) {
	options := UsernamePasswordCredentialOptions{}
	cred, err := NewUsernamePasswordCredential(tenantID, clientID, "username", "wrong_password", &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		err: errors.New("bad user-name or password"),
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

func TestBearerPolicy_UsernamePasswordCredential(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusOK))
	options := UsernamePasswordCredentialOptions{}
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewUsernamePasswordCredential(tenantID, clientID, "username", "password", &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	pipeline := defaultTestPipeline(srv, cred, scope)
	req, err := azcore.NewRequest(context.Background(), http.MethodGet, srv.URL())
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipeline.Do(req)
	if err != nil {
		t.Fatalf("Expected an empty error but receive: %v", err)
	}
}
