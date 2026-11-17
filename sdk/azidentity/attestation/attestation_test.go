// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package attestation_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity/attestation"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportedAttestation(t *testing.T) {
	for _, name := range []string{
		"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "IMDS_ENDPOINT",
		"MSI_ENDPOINT", "MSI_SECRET", "AZURE_POD_IDENTITY_AUTHORITY_HOST", "MSAL_MI_DISABLE_IMDS_V2",
	} {
		t.Setenv(name, "")
	}
	for _, tc := range []struct {
		name                string
		requestPoP, disable bool
	}{
		{name: "discover unsupported host", requestPoP: true},
		{name: "opt out", requestPoP: true, disable: true},
		{name: "ordinary bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, close := mock.NewServer(mock.WithTransformAllRequestsToTestServerUrl())
			defer close()
			wantPaths := []string{"/metadata/identity/oauth2/token"}
			if tc.requestPoP && !tc.disable {
				// A definitive v2 absence and Standard VM metadata avoid native operations on every platform.
				srv.AppendResponse(mock.WithStatusCode(http.StatusNotFound))
				srv.AppendResponse(mock.WithStatusCode(http.StatusBadRequest))
				srv.AppendResponse(mock.WithBody([]byte(`{"securityProfile":{"securityType":"Standard"}}`)))
				wantPaths = []string{
					"/metadata/identity/getplatformmetadata", "/metadata/identity/oauth2/token",
					"/metadata/instance/compute", "/metadata/identity/oauth2/token",
				}
			}
			srv.AppendResponse(mock.WithBody([]byte(`{"access_token":"bearer-token","expires_in":3600,"token_type":"Bearer"}`)))
			var paths []string
			cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				DisableMTLSPoP: tc.disable,
				ClientOptions: azcore.ClientOptions{
					Transport: srv,
					Retry:     policy.RetryOptions{MaxRetries: -1},
					PerCallPolicies: []policy.Policy{policyFunc(func(req *policy.Request) (*http.Response, error) {
						paths = append(paths, req.Raw().URL.Path)
						return req.Next()
					})},
				},
			})
			require.NoError(t, err)
			assert.Empty(t, paths, "constructing an activated credential must not perform discovery")
			tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
				Scopes: []string{"https://example.com/" + rand.Text()}, EnableMTLSPoP: tc.requestPoP,
			})
			require.NoError(t, err)
			assert.Equal(t, "bearer-token", tk.Token)
			assert.Nil(t, tk.BindingCertificate)
			assert.Equal(t, wantPaths, paths, "the blank import must activate capability discovery only for eligible requests")
		})
	}
}

type policyFunc func(*policy.Request) (*http.Response, error)

func (f policyFunc) Do(req *policy.Request) (*http.Response, error) {
	return f(req)
}
