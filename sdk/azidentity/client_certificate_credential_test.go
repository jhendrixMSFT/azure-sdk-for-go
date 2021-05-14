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
	certificatePath      = "testdata/certificate.pem"
	wrongCertificatePath = "wrong_certificate_path.pem"
)

func TestClientCertificateCredential_InvalidTenantID(t *testing.T) {
	cred, err := NewClientCertificateCredential(badTenantID, clientID, certificatePath, nil)
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

func TestClientCertificateCredential_GetTokenSuccess(t *testing.T) {
	cred, err := NewClientCertificateCredential(tenantID, clientID, certificatePath, nil)
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
	cred.client = fakeConfidentialClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
}

func TestClientCertificateCredential_GetTokenInvalidCredentials(t *testing.T) {
	cred, err := NewClientCertificateCredential(tenantID, clientID, certificatePath, nil)
	if err != nil {
		t.Fatalf("Did not expect an error but received one: %v", err)
	}
	cred.client = fakeConfidentialClient{
		err: errors.New("unauthorized"),
	}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatalf("Expected to receive a nil error, but received: %v", err)
	}
	var authFailed AuthenticationFailedError
	if !errors.As(err, &authFailed) {
		t.Fatalf("Expected: AuthenticationFailedError, Received: %T", err)
	}
}

func TestClientCertificateCredential_WrongCertificatePath(t *testing.T) {
	_, err := NewClientCertificateCredential(tenantID, clientID, wrongCertificatePath, nil)
	if err == nil {
		t.Fatalf("Expected an error but did not receive one")
	}
	var errType CredentialUnavailableError
	if !errors.As(err, &errType) {
		t.Fatalf("Did not receive a CredentialUnavailableError. Received: %t", err)
	}
}

func TestClientCertificateCredential_GetTokenCheckPrivateKeyBlocks(t *testing.T) {
	cred, err := NewClientCertificateCredential(tenantID, clientID, "testdata/certificate_formatB.pem", nil)
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
	cred.client = fakeConfidentialClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
}

func TestClientCertificateCredential_GetTokenCheckCertificateBlocks(t *testing.T) {
	cred, err := NewClientCertificateCredential(tenantID, clientID, "testdata/certificate_formatA.pem", nil)
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
	cred.client = fakeConfidentialClient{}
	_, err = cred.GetToken(context.Background(), azcore.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
}

func TestClientCertificateCredential_GetTokenEmptyCertificate(t *testing.T) {
	_, err := NewClientCertificateCredential(tenantID, clientID, "testdata/certificate_empty.pem", nil)
	if err == nil {
		t.Fatalf("Expected an error but received nil")
	}
	var errType CredentialUnavailableError
	if !errors.As(err, &errType) {
		t.Fatalf("Did not receive a CredentialUnavailableError. Received: %t", err)
	}
}

func TestClientCertificateCredential_GetTokenNoPrivateKey(t *testing.T) {
	_, err := NewClientCertificateCredential(tenantID, clientID, "testdata/certificate_nokey.pem", nil)
	if err == nil {
		t.Fatalf("Expected an error but received nil")
	}
	var errType CredentialUnavailableError
	if !errors.As(err, &errType) {
		t.Fatalf("Did not receive a CredentialUnavailableError. Received: %t", err)
	}
}

func TestBearerPolicy_ClientCertificateCredential(t *testing.T) {
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespSuccess)))
	srv.AppendResponse(mock.WithStatusCode(http.StatusOK))
	options := ClientCertificateCredentialOptions{}
	options.AuthorityHost = srv.URL()
	options.HTTPClient = srv
	cred, err := NewClientCertificateCredential(tenantID, clientID, certificatePath, &options)
	if err != nil {
		t.Fatalf("Did not expect an error but received: %v", err)
	}
	cred.client = fakeConfidentialClient{}
	pipeline := defaultTestPipeline(srv, cred, scope)
	req, err := azcore.NewRequest(context.Background(), http.MethodGet, srv.URL())
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipeline.Do(req)
	if err != nil {
		t.Fatalf("Expected nil error but received one")
	}
}
