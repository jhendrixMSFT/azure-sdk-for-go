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
	tenantID                 = "expected-tenant"
	badTenantID              = "bad_tenant"
	clientID                 = "expected_client"
	secret                   = "secret"
	wrongSecret              = "wrong_secret"
	tokenValue               = "new_token"
	scope                    = "https://storage.azure.com/.default"
	defaultTestAuthorityHost = "login.microsoftonline.com"
)

func TestClientSecretCredential_InvalidTenantID(t *testing.T) {
	cred, err := NewClientSecretCredential(badTenantID, clientID, secret, nil)
	if err == nil {
		t.Fatal("Expected an error but received none")
	}
	if cred != nil {
		t.Fatalf("Expected a nil credential value. Received: %v", cred)
	}
	var errType *CredentialUnavailableError
	if !errors.As(err, &errType) {
		t.Fatalf("Did not receive a CredentialUnavailableError. Received: %t", err)
	}
}

func TestClientSecretCredential_GetTokenSuccess(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespSuccess)))
	options := ClientSecretCredentialOptions{}
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewClientSecretCredential(tenantID, clientID, secret, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %v", err)
	}
}

func TestClientSecretCredential_GetTokenInvalidCredentials(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.SetResponse(mock.WithBody([]byte(accessTokenRespError)), mock.WithStatusCode(http.StatusUnauthorized))
	options := ClientSecretCredentialOptions{}
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewClientSecretCredential(tenantID, clientID, wrongSecret, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one.")
	}
	var authFailed *AuthenticationFailedError
	if !errors.As(err, &authFailed) {
		t.Fatalf("Expected: AuthenticationFailedError, Received: %T", err)
	} else {
		var respError *AADAuthenticationFailedError
		if !errors.As(authFailed.Unwrap(), &respError) {
			t.Fatalf("Expected: AADAuthenticationFailedError, Received: %T", err)
		} else {
			if len(respError.Message) == 0 {
				t.Fatalf("Did not receive an error message")
			}
			if len(respError.Description) == 0 {
				t.Fatalf("Did not receive an error description")
			}
			if len(respError.Timestamp) == 0 {
				t.Fatalf("Did not receive a timestamp")
			}
			if len(respError.TraceID) == 0 {
				t.Fatalf("Did not receive a TraceID")
			}
			if len(respError.CorrelationID) == 0 {
				t.Fatalf("Did not receive a CorrelationID")
			}
			if len(respError.URL) == 0 {
				t.Fatalf("Did not receive an error URL")
			}
			if respError.Response == nil {
				t.Fatalf("Did not receive an error response")
			}
		}
	}
}

func TestClientSecretCredential_GetTokenUnexpectedJSON(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespMalformed)))
	options := ClientSecretCredentialOptions{}
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewClientSecretCredential(tenantID, clientID, secret, &options)
	if err != nil {
		t.Fatalf("Failed to create the credential")
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatalf("Expected a JSON marshal error but received nil")
	}
}
