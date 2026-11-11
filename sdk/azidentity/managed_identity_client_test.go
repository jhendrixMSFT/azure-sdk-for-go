// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type userAgentValidatingPolicy struct {
	t     *testing.T
	appID string
}

func (p userAgentValidatingPolicy) Do(req *policy.Request) (*http.Response, error) {
	expected := "azsdk-go-" + component + "/" + version
	if p.appID != "" {
		expected = p.appID + " " + expected
	}
	if ua := req.Raw().Header.Get("User-Agent"); !strings.HasPrefix(ua, expected) {
		p.t.Fatalf("unexpected User-Agent %s", ua)
	}
	return req.Next()
}

func TestManagedIdentityCredential_UserAgent(t *testing.T) {
	for _, appID := range []string{"", "customvalue"} {
		options := ManagedIdentityCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: &mockSTS{}, PerCallPolicies: []policy.Policy{userAgentValidatingPolicy{t: t, appID: appID}},
			},
		}

		c, err := NewManagedIdentityCredential(&options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{t.Name()}})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestManagedIdentityCredential_MTLSPoP(t *testing.T) {
	setEnvironmentVariables(t, map[string]string{
		identityEndpoint: "http://localhost/identity", identityHeader: "secret",
		identityServerThumbprint: "", msiEndpoint: "", msiSecret: "", arcIMDSEndpoint: "",
	})
	// App Service rejects the mTLS option before making any HTTP request.
	msal, err := managedidentity.New(managedidentity.SystemAssigned())
	require.NoError(t, err)
	c, err := NewManagedIdentityCredential(nil)
	require.NoError(t, err)
	c.mic.msalClient = fakeManagedIdentityClient{acquireToken: func(ctx context.Context, resource string, opts ...managedidentity.AcquireTokenOption) (managedidentity.AuthResult, error) {
		assert.Equal(t, "https://vault.azure.net", resource)
		return msal.AcquireToken(ctx, resource, opts...)
	}}
	token, err := c.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://vault.azure.net/.default"}, EnableMTLSPoP: true,
	})
	require.ErrorContains(t, err, managedidentity.ErrMtlsPoPNotSupportedForSource.Error())
	var authErr *AuthenticationFailedError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, azcore.AccessToken{}, token)
}

func TestManagedIdentityCredential_MTLSPoPIdentitySelection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("MSAL supports IMDSv2 mTLS PoP only on Windows")
	}
	setEnvironmentVariables(t, map[string]string{
		identityEndpoint: "", identityHeader: "", identityServerThumbprint: "",
		msiEndpoint: "", msiSecret: "", arcIMDSEndpoint: "",
		"MSAL_MI_DISABLE_IMDS_V2": "",
	})
	for _, tc := range []struct {
		name, parameter string
		id              ManagedIDKind
	}{
		{name: "system assigned"},
		{name: "client ID", parameter: "client_id", id: ClientID("11111111-2222-3333-4444-555555555555")},
		{name: "object ID", parameter: "object_id", id: ObjectID("22222222-3333-4444-5555-666666666666")},
		{name: "resource ID", parameter: "mi_res_id", id: ResourceID("/subscriptions/test/resourceGroups/test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, close := mock.NewServer(mock.WithTransformAllRequestsToTestServerUrl())
			defer close()
			// Stop at metadata discovery, before any native key or certificate-store operation.
			srv.SetResponse(mock.WithStatusCode(http.StatusBadRequest), mock.WithHeader("Server", "IMDS"),
				mock.WithBody([]byte(`{"error":"invalid_request","error_description":"offline metadata rejection"}`)))
			wantQuery := url.Values{"cred-api-version": {"2.0"}}
			if tc.id != nil {
				wantQuery.Set(tc.parameter, tc.id.String())
			}
			c, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{
				ID: tc.id, EnableAttestation: true,
				ClientOptions: azcore.ClientOptions{
					Transport: srv,
					Retry:     policy.RetryOptions{MaxRetries: -1},
					PerCallPolicies: []policy.Policy{managedIdentityTestPolicy{do: func(req *policy.Request) {
						raw := req.Raw()
						assert.Equal(t, http.MethodGet, raw.Method)
						assert.Equal(t, "169.254.169.254", raw.URL.Host)
						assert.Equal(t, "/metadata/identity/getplatformmetadata", raw.URL.Path)
						assert.Equal(t, wantQuery, raw.URL.Query())
						assert.Equal(t, "true", raw.Header.Get("Metadata"))
						assert.NotEmpty(t, raw.Header.Get("x-ms-client-request-id"))
						assert.Contains(t, raw.Header.Get("User-Agent"), "azsdk-go-azidentity/")
					}}},
				},
			})
			require.NoError(t, err)
			token, err := c.GetToken(context.Background(), policy.TokenRequestOptions{
				Scopes: []string{t.Name()}, EnableMTLSPoP: true,
			})
			require.ErrorContains(t, err, "offline metadata rejection")
			var authErr *AuthenticationFailedError
			require.ErrorAs(t, err, &authErr)
			assert.Equal(t, azcore.AccessToken{}, token)
			assert.Equal(t, 1, srv.Requests(), "a failed mTLS request must not fall back to IMDSv1")
		})
	}
}

func TestManagedIdentityCredential_Attestation(t *testing.T) {
	setEnvironmentVariables(t, map[string]string{
		identityEndpoint: "", identityHeader: "", identityServerThumbprint: "",
		msiEndpoint: "", msiSecret: "", arcIMDSEndpoint: "",
	})
	for _, tc := range []struct {
		name              string
		enableAttestation bool
		enableMTLSPoP     bool
		wantOptions       []managedidentity.AcquireTokenOption
		tokenErr          error
	}{
		{
			name: "unattested PoP", enableMTLSPoP: true,
			wantOptions: []managedidentity.AcquireTokenOption{managedidentity.WithMtlsProofOfPossession()},
		},
		{
			name: "bearer with attestation enabled", enableAttestation: true,
		},
		{
			name: "attested PoP", enableAttestation: true, enableMTLSPoP: true,
			wantOptions: []managedidentity.AcquireTokenOption{
				managedidentity.WithMtlsProofOfPossession(), managedidentity.WithAttestationSupport(),
			},
		},
		{
			name: "attestation unavailable", enableAttestation: true, enableMTLSPoP: true,
			wantOptions: []managedidentity.AcquireTokenOption{
				managedidentity.WithMtlsProofOfPossession(), managedidentity.WithAttestationSupport(),
			},
			tokenErr: managedidentity.ErrAttestationUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{EnableAttestation: tc.enableAttestation})
			require.NoError(t, err)
			const claims = `{"access_token":{"test":"claim"}}`
			var want managedidentity.AcquireTokenOptions
			managedidentity.WithClaims(claims)(&want)
			for _, opt := range tc.wantOptions {
				opt(&want)
			}
			calls := 0
			c.mic.msalClient = fakeManagedIdentityClient{acquireToken: func(_ context.Context, resource string, opts ...managedidentity.AcquireTokenOption) (managedidentity.AuthResult, error) {
				calls++
				assert.Equal(t, "https://vault.azure.net", resource)
				var got managedidentity.AcquireTokenOptions
				for _, opt := range opts {
					opt(&got)
				}
				assert.Equal(t, want, got)
				if tc.tokenErr != nil {
					return managedidentity.AuthResult{}, tc.tokenErr
				}
				return managedidentity.AuthResult{AccessToken: tokenValue}, nil
			}}
			token, err := c.GetToken(context.Background(), policy.TokenRequestOptions{
				Scopes: []string{"https://vault.azure.net/.default"}, Claims: claims, EnableMTLSPoP: tc.enableMTLSPoP,
			})
			assert.Equal(t, 1, calls, "attestation failure must not trigger an unattested fallback")
			if tc.tokenErr != nil {
				require.ErrorContains(t, err, tc.tokenErr.Error())
				var authErr *AuthenticationFailedError
				require.ErrorAs(t, err, &authErr)
				assert.Equal(t, azcore.AccessToken{}, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tokenValue, token.Token)
			}
		})
	}
}

func TestManagedIdentityCredential_BindingCertificate(t *testing.T) {
	c, err := NewManagedIdentityCredential(nil)
	require.NoError(t, err)
	cert := &tls.Certificate{}
	now := time.Now()
	for _, bound := range []bool{false, true} {
		ar := managedidentity.AuthResult{AccessToken: tokenValue, ExpiresOn: now}
		ar.Metadata.RefreshOn = now.Add(-time.Minute)
		if bound {
			ar.BindingCertificate = cert
		}
		c.mic.msalClient = fakeManagedIdentityClient{ar: ar}
		token, err := c.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{t.Name()}, EnableMTLSPoP: bound})
		require.NoError(t, err)
		assert.Equal(t, tokenValue, token.Token)
		assert.Equal(t, now.UTC(), token.ExpiresOn)
		assert.Equal(t, ar.Metadata.RefreshOn.UTC(), token.RefreshOn)
		assert.Same(t, ar.BindingCertificate, token.BindingCertificate)
	}
}

func TestManagedIdentityClient_MTLSFactory(t *testing.T) {
	setEnvironmentVariables(t, map[string]string{
		identityEndpoint: "", identityHeader: "", identityServerThumbprint: "",
		msiEndpoint: "", msiSecret: "", arcIMDSEndpoint: "",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("User-Agent"), "azsdk-go-azidentity/")
		assert.Equal(t, "present", r.Header.Get("Test-Policy"))
		_, err := io.WriteString(w, "{}")
		assert.NoError(t, err)
	}))
	defer server.Close()
	base := server.Client()
	var policyCalls int
	c, err := newManagedIdentityClient(&ManagedIdentityCredentialOptions{ClientOptions: azcore.ClientOptions{
		Transport: base,
		PerCallPolicies: []policy.Policy{managedIdentityTestPolicy{do: func(req *policy.Request) {
			policyCalls++
			req.Raw().Header.Set("Test-Policy", "present")
		}}},
	}})
	require.NoError(t, err)
	first, err := c.NewMtlsClient()
	require.NoError(t, err)
	second, err := c.NewMtlsClient()
	require.NoError(t, err)
	assert.NotSame(t, first, second)
	var configured *http.Client
	augment := func(got *http.Client) (*http.Client, error) {
		assert.Same(t, base, got)
		copy := *got
		configured = &copy
		return configured, nil
	}
	require.NoError(t, first.ConfigureClient(augment))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	resp, err := first.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, 1, policyCalls)
	require.Nil(t, c.configurableClient.client, "the shared pipeline must not be reconfigured")
	first.CloseIdleConnections()
	c.CloseIdleConnections()
	expectedErr := errors.New("augmentation failed")
	require.ErrorIs(t, second.ConfigureClient(func(*http.Client) (*http.Client, error) { return nil, expectedErr }), expectedErr)
}

type managedIdentityTestPolicy struct {
	do func(*policy.Request)
}

func (p managedIdentityTestPolicy) Do(req *policy.Request) (*http.Response, error) {
	p.do(req)
	return req.Next()
}

func TestManagedIdentityClient_MTLSFactoryCustomTransport(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	c := &managedIdentityClient{clientOptions: azcore.ClientOptions{Transport: srv}}
	_, err := c.NewMtlsClient()
	require.ErrorContains(t, err, "*http.Client")
}

func TestManagedIdentityClient_MTLSFactoryCleanup(t *testing.T) {
	baseTransport := &managedIdentityIdleTransport{}
	base := &http.Client{Transport: baseTransport}
	c := &managedIdentityClient{clientOptions: azcore.ClientOptions{Transport: base}}
	child, err := c.NewMtlsClient()
	require.NoError(t, err)
	childTransport := &managedIdentityIdleTransport{}
	require.NoError(t, child.ConfigureClient(func(got *http.Client) (*http.Client, error) {
		require.Same(t, base, got)
		return &http.Client{Transport: childTransport}, nil
	}))
	child.CloseIdleConnections()
	c.CloseIdleConnections()
	assert.Equal(t, 1, childTransport.closed)
	assert.Zero(t, baseTransport.closed, "MSAL cleanup must never close the caller's pool")
}

type managedIdentityIdleTransport struct {
	closed int
}

func (*managedIdentityIdleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func (t *managedIdentityIdleTransport) CloseIdleConnections() {
	t.closed++
}
