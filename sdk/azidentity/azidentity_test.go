// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	envHostString    = "https://mock.com/"
	customHostString = "https://custommock.com/"
)

func Test_AuthorityHost_Parse(t *testing.T) {
	_, err := url.Parse(AzurePublicCloud)
	if err != nil {
		t.Fatalf("Failed to parse default authority host: %v", err)
	}
}

func Test_SetEnvAuthorityHost(t *testing.T) {
	err := os.Setenv("AZURE_AUTHORITY_HOST", envHostString)
	defer func() {
		// Unset that host environment variable to avoid other tests failed.
		err = os.Unsetenv("AZURE_AUTHORITY_HOST")
		if err != nil {
			t.Fatalf("Unexpected error when unset environment variable: %v", err)
		}
	}()
	if err != nil {
		t.Fatalf("Unexpected error when initializing environment variables: %v", err)
	}
	authorityHost, err := setAuthorityHost("")
	if err != nil {
		t.Fatal(err)
	}
	if authorityHost != envHostString {
		t.Fatalf("Unexpected error when get host from environment variable: %v", err)
	}
}

func Test_CustomAuthorityHost(t *testing.T) {
	err := os.Setenv("AZURE_AUTHORITY_HOST", envHostString)
	defer func() {
		// Unset that host environment variable to avoid other tests failed.
		err = os.Unsetenv("AZURE_AUTHORITY_HOST")
		if err != nil {
			t.Fatalf("Unexpected error when unset environment variable: %v", err)
		}
	}()
	if err != nil {
		t.Fatalf("Unexpected error when initializing environment variables: %v", err)
	}
	authorityHost, err := setAuthorityHost(customHostString)
	if err != nil {
		t.Fatal(err)
	}
	// ensure env var doesn't override explicit value
	if authorityHost != customHostString {
		t.Fatalf("Unexpected host when get host from environment variable: %v", authorityHost)
	}
}

func Test_DefaultAuthorityHost(t *testing.T) {
	authorityHost, err := setAuthorityHost("")
	if err != nil {
		t.Fatal(err)
	}
	if authorityHost != AzurePublicCloud {
		t.Fatalf("Unexpected host when set default AuthorityHost: %v", authorityHost)
	}
}

func Test_AzureGermanyAuthorityHost(t *testing.T) {
	authorityHost, err := setAuthorityHost(AzureGermany)
	if err != nil {
		t.Fatal(err)
	}
	if authorityHost != AzureGermany {
		t.Fatalf("Did not retrieve expected authority host string")
	}
}

func Test_AzureChinaAuthorityHost(t *testing.T) {
	authorityHost, err := setAuthorityHost(AzureChina)
	if err != nil {
		t.Fatal(err)
	}
	if authorityHost != AzureChina {
		t.Fatalf("Did not retrieve expected authority host string")
	}
}

func Test_AzureGovernmentAuthorityHost(t *testing.T) {
	authorityHost, err := setAuthorityHost(AzureGovernment)
	if err != nil {
		t.Fatal(err)
	}
	if authorityHost != AzureGovernment {
		t.Fatalf("Did not retrieve expected authority host string")
	}
}

func Test_NonHTTPSAuthorityHost(t *testing.T) {
	authorityHost, err := setAuthorityHost("http://foo.com")
	if err == nil {
		t.Fatal("Expected an error but did not receive one.")
	}
	if authorityHost != "" {
		t.Fatalf("Unexpected value in authority host string: %s", authorityHost)
	}
}

func Test_ValidTenantIDFalse(t *testing.T) {
	if validTenantID("bad@tenant") {
		t.Fatal("Expected to receive false, but received true")
	}
	if validTenantID("bad/tenant") {
		t.Fatal("Expected to receive false, but received true")
	}
	if validTenantID("bad(tenant") {
		t.Fatal("Expected to receive false, but received true")
	}
	if validTenantID("bad)tenant") {
		t.Fatal("Expected to receive false, but received true")
	}
	if validTenantID("bad:tenant") {
		t.Fatal("Expected to receive false, but received true")
	}
}

func Test_ValidTenantIDTrue(t *testing.T) {
	if !validTenantID("goodtenant") {
		t.Fatal("Expected to receive true, but received false")
	}
	if !validTenantID("good-tenant") {
		t.Fatal("Expected to receive true, but received false")
	}
	if !validTenantID("good.tenant") {
		t.Fatal("Expected to receive true, but received false")
	}
}

// ==================================================================================================================================

type fakeConfidentialClient struct {
	// set ar to have all API calls return the provided AuthResult
	ar confidential.AuthResult

	// set err to have all API calls return the provided error
	err error
}

func (f fakeConfidentialClient) returnResult() (confidential.AuthResult, error) {
	if f.err != nil {
		return confidential.AuthResult{}, f.err
	}
	return f.ar, nil
}

func (f fakeConfidentialClient) AcquireTokenSilent(ctx context.Context, scopes []string, options ...confidential.AcquireTokenSilentOption) (confidential.AuthResult, error) {
	return f.returnResult()
}

func (f fakeConfidentialClient) AcquireTokenByAuthCode(ctx context.Context, code string, redirectURI string, scopes []string, options ...confidential.AcquireTokenByAuthCodeOption) (confidential.AuthResult, error) {
	return f.returnResult()
}

func (f fakeConfidentialClient) AcquireTokenByCredential(ctx context.Context, scopes []string) (confidential.AuthResult, error) {
	return f.returnResult()
}

var _ confidentialClient = (*fakeConfidentialClient)(nil)

// ==================================================================================================================================

type fakePublicClient struct {
	// set ar to have all API calls return the provided AuthResult
	ar public.AuthResult

	// similar to ar but for device code APIs
	dc public.DeviceCode

	// set err to have all API calls return the provided error
	err error
}

func (f fakePublicClient) returnResult() (public.AuthResult, error) {
	if f.err != nil {
		return public.AuthResult{}, f.err
	}
	return f.ar, nil
}

func (f fakePublicClient) AcquireTokenSilent(ctx context.Context, scopes []string, options ...public.AcquireTokenSilentOption) (public.AuthResult, error) {
	return f.returnResult()
}

func (f fakePublicClient) AcquireTokenByUsernamePassword(ctx context.Context, scopes []string, username string, password string) (public.AuthResult, error) {
	return f.returnResult()
}

func (f fakePublicClient) AcquireTokenByDeviceCode(ctx context.Context, scopes []string) (public.DeviceCode, error) {
	if f.err != nil {
		return public.DeviceCode{}, f.err
	}
	return f.dc, nil
}

func (f fakePublicClient) AcquireTokenByAuthCode(ctx context.Context, code string, redirectURI string, scopes []string, options ...public.AcquireTokenByAuthCodeOption) (public.AuthResult, error) {
	return f.returnResult()
}

func (f fakePublicClient) AcquireTokenInteractive(ctx context.Context, scopes []string, options ...public.InteractiveAuthOption) (public.AuthResult, error) {
	return f.returnResult()
}

var _ publicClient = (*fakePublicClient)(nil)
