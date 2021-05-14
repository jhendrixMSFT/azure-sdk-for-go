// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
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
	options := AuthorizationCodeCredentialOptions{}
	options.ClientSecret = secret
	cred, err := NewAuthorizationCodeCredential(tenantID, clientID, testAuthCode, testRedirectURI, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %v", err)
	}
}

func TestAuthorizationCodeCredential_GetTokenInvalidCredentials(t *testing.T) {
	options := AuthorizationCodeCredentialOptions{}
	options.ClientSecret = secret
	cred, err := NewAuthorizationCodeCredential(tenantID, clientID, testAuthCode, testRedirectURI, &options)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		err: errors.New(accessTokenRespError),
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
