// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testToken(t *testing.T) azcore.AccessToken {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	hash := sha256.Sum256(der)
	payload, err := json.Marshal(map[string]any{
		"cnf": map[string]string{"x5t#S256": base64.RawURLEncoding.EncodeToString(hash[:])},
	})
	require.NoError(t, err)
	return azcore.AccessToken{
		Token:     "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".test-signature",
		ExpiresOn: time.Now().Add(time.Hour),
		BindingCertificate: &tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  private,
			Leaf:        leaf,
		},
	}
}

func TestConfiguration(t *testing.T) {
	base := configuration{vaultURL: "https://example.vault.azure.net", secretName: "test-secret", timeout: time.Minute}
	require.NoError(t, base.validate())
	assert.Nil(t, base.identity())
	for _, tc := range []struct {
		name string
		edit func(*configuration)
	}{
		{"missing vault", func(c *configuration) { c.vaultURL = "" }},
		{"http", func(c *configuration) { c.vaultURL = "http://example.vault.azure.net" }},
		{"userinfo", func(c *configuration) { c.vaultURL = "https://user@example.vault.azure.net" }},
		{"path", func(c *configuration) { c.vaultURL += "/secrets" }},
		{"query", func(c *configuration) { c.vaultURL += "?a=b" }},
		{"fragment", func(c *configuration) { c.vaultURL += "#fragment" }},
		{"empty secret", func(c *configuration) { c.secretName = "" }},
		{"secret path", func(c *configuration) { c.secretName = "a/b" }},
		{"timeout", func(c *configuration) { c.timeout = 0 }},
		{"multiple identities", func(c *configuration) { c.clientID, c.objectID = "client", "object" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			require.Error(t, cfg.validate())
		})
	}
	for _, tc := range []struct {
		cfg configuration
		id  azidentity.ManagedIDKind
	}{
		{configuration{clientID: "client"}, azidentity.ClientID("client")},
		{configuration{objectID: "object"}, azidentity.ObjectID("object")},
		{configuration{resourceID: "resource"}, azidentity.ResourceID("resource")},
	} {
		assert.Equal(t, tc.id, tc.cfg.identity())
	}
}

func TestValidateBound(t *testing.T) {
	token := testToken(t)
	hash := sha256.Sum256(token.BindingCertificate.Certificate[0])
	thumbprint, err := validateBound(token, time.Now())
	require.NoError(t, err)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), thumbprint)

	for _, tc := range []struct {
		name    string
		edit    func(*azcore.AccessToken)
		message string
	}{
		{"empty", func(tk *azcore.AccessToken) { tk.Token = "" }, "nonempty"},
		{"expired", func(tk *azcore.AccessToken) { tk.ExpiresOn = time.Now().Add(-time.Minute) }, "unexpired"},
		{"no certificate", func(tk *azcore.AccessToken) { tk.BindingCertificate = nil }, "binding certificate"},
		{"no DER", func(tk *azcore.AccessToken) { tk.BindingCertificate.Certificate = nil }, "binding certificate"},
		{"bad DER", func(tk *azcore.AccessToken) { tk.BindingCertificate.Certificate[0] = []byte("bad") }, "parsing"},
		{"no key", func(tk *azcore.AccessToken) { tk.BindingCertificate.PrivateKey = nil }, "private key"},
		{"not signer", func(tk *azcore.AccessToken) { tk.BindingCertificate.PrivateKey = "bad" }, "crypto.Signer"},
		{"wrong key", func(tk *azcore.AccessToken) { tk.BindingCertificate.PrivateKey = token.BindingCertificate.PrivateKey }, "doesn't match"},
		{"not JWT", func(tk *azcore.AccessToken) { tk.Token = "opaque" }, "three-part JWT"},
		{"bad base64", func(tk *azcore.AccessToken) { tk.Token = "e30.!.signature" }, "payload"},
		{"bad JSON", func(tk *azcore.AccessToken) {
			tk.Token = "e30." + base64.RawURLEncoding.EncodeToString([]byte("{")) + ".sig"
		}, "claims"},
		{"missing cnf", func(tk *azcore.AccessToken) { tk.Token = "e30.e30.signature" }, "cnf.x5t#S256"},
		{"wrong cnf", func(tk *azcore.AccessToken) { tk.Token = token.Token }, "doesn't match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tk := testToken(t)
			tc.edit(&tk)
			_, err := validateBound(tk, time.Now())
			require.ErrorContains(t, err, tc.message)
		})
	}
	_, err = validateBound(token, token.BindingCertificate.Leaf.NotBefore.Add(-time.Second))
	require.ErrorContains(t, err, "isn't currently valid")
	token.ExpiresOn = token.BindingCertificate.Leaf.NotAfter.Add(time.Hour)
	_, err = validateBound(token, token.BindingCertificate.Leaf.NotAfter)
	require.ErrorContains(t, err, "isn't currently valid")
	// Parsing DER, rather than trusting a potentially absent Leaf, also supports callers constructing certificates.
	token.BindingCertificate.Leaf = nil
	_, err = validateBound(token, time.Now())
	require.NoError(t, err)
}

func TestValidateBearer(t *testing.T) {
	require.NoError(t, validateBearer(azcore.AccessToken{Token: "bearer", ExpiresOn: time.Now().Add(time.Hour)}))
	require.Error(t, validateBearer(azcore.AccessToken{}))
	require.Error(t, validateBearer(azcore.AccessToken{Token: "expired", ExpiresOn: time.Now().Add(-time.Hour)}))
	require.Error(t, validateBearer(testToken(t)))
}

func TestValidateRejection(t *testing.T) {
	body := []byte(`{"error":{"code":"MissingClientCertificate"}}`)
	require.NoError(t, validateRejection(http.StatusUnauthorized, body))
	require.NoError(t, validateRejection(http.StatusForbidden, body))
	for _, status := range []int{200, 302, 500, 503} {
		require.Error(t, validateRejection(status, body))
	}
	require.Error(t, validateRejection(http.StatusForbidden, []byte(`{"error":{"code":"Forbidden"}}`)))
}

func TestResourceGET(t *testing.T) {
	token := testToken(t)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "mtls_pop "+token.Token, r.Header.Get("Authorization"))
		assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
		assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte(`{"error":{"code":"MissingClientCertificate"}}`))
			assert.NoError(t, err)
			return
		}
		assert.Equal(t, token.BindingCertificate.Certificate[0], r.TLS.PeerCertificates[0].Raw)
		_, err := w.Write([]byte(`{"value":"not-logged"}`))
		assert.NoError(t, err)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, present := range []bool{true, false} {
		cert := token.BindingCertificate
		if !present {
			cert = nil
		}
		client := newResourceClient(cert, roots)
		t.Cleanup(client.CloseIdleConnections)
		status, body, err := resourceGET(context.Background(), client, server.URL, token.Token)
		require.NoError(t, err)
		if present {
			assert.Equal(t, http.StatusOK, status)
		} else {
			require.NoError(t, validateRejection(status, body))
		}
	}
	assert.Equal(t, int32(2), requests.Load())
}

func TestResourceGETFailures(t *testing.T) {
	var redirected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/destination", http.StatusFound)
		case "/destination":
			redirected.Add(1)
		case "/large":
			_, err := w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
			assert.NoError(t, err)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := newResourceClient(nil, roots)
	defer client.CloseIdleConnections()
	_, _, err := resourceGET(context.Background(), client, server.URL+"/redirect", "token")
	require.ErrorContains(t, err, "redirects aren't permitted")
	assert.Zero(t, redirected.Load())
	_, _, err = resourceGET(context.Background(), client, server.URL+"/large", "token")
	require.ErrorContains(t, err, "exceeds 1 MiB")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = resourceGET(ctx, client, server.URL, "token")
	require.ErrorIs(t, err, context.Canceled)
}

type tokenCredentialFunc func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f tokenCredentialFunc) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, options)
}

func TestCheckedCredential(t *testing.T) {
	token := testToken(t)
	called := false
	credential := &checkedCredential{credential: tokenCredentialFunc(func(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
		called = true
		assert.True(t, options.EnableMTLSPoP)
		assert.Equal(t, []string{vaultScope}, options.Scopes)
		return token, nil
	})}
	_, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{})
	require.ErrorContains(t, err, "didn't propagate")
	assert.False(t, called)
	_, err = credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{vaultScope}, EnableMTLSPoP: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), credential.calls.Load())
	credential.credential = tokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return azcore.AccessToken{Token: "unbound", ExpiresOn: time.Now().Add(time.Hour)}, nil
	})
	_, err = credential.GetToken(context.Background(), policy.TokenRequestOptions{EnableMTLSPoP: true})
	require.ErrorContains(t, err, "binding certificate")
	failure := errors.New("acquisition failed")
	credential.credential = tokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return azcore.AccessToken{}, failure
	})
	_, err = credential.GetToken(context.Background(), policy.TokenRequestOptions{EnableMTLSPoP: true})
	require.ErrorIs(t, err, failure)
}

func TestAutomaticPipeline(t *testing.T) {
	token := testToken(t)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "mtls_pop "+token.Token, r.Header.Get("Authorization"))
		assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
		assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
		if assert.Len(t, r.TLS.PeerCertificates, 1) {
			assert.Equal(t, token.BindingCertificate.Certificate[0], r.TLS.PeerCertificates[0].Raw)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	credential := &checkedCredential{credential: tokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return token, nil
	})}
	pipeline := runtime.NewPipeline("mtls-pop-smoke", "v0.0.0", runtime.PipelineOptions{
		PerRetry: []policy.Policy{runtime.NewBearerTokenPolicy(credential, []string{vaultScope}, nil)},
	}, &policy.ClientOptions{EnableMTLSPoP: true, Transport: server.Client()})
	for range 2 {
		req, err := runtime.NewRequest(context.Background(), http.MethodGet, server.URL)
		require.NoError(t, err)
		resp, err := pipeline.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, int32(1), credential.calls.Load(), "the automatic pipeline should reuse its cached token")
}

func TestKeyVaultSDKColdChallenge(t *testing.T) {
	token := testToken(t)
	var requests, challenges atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "/secrets/test-secret/", r.URL.Path)
		assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
		if r.Header.Get("Authorization") == "" {
			challenges.Add(1)
			assert.Empty(t, r.TLS.PeerCertificates)
			assert.Empty(t, r.Header.Get("x-ms-tokenboundauth"))
			w.Header().Set("WWW-Authenticate",
				`Bearer authorization="https://login.microsoftonline.com/tenant" resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "mtls_pop "+token.Token, r.Header.Get("Authorization"))
		assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
		if assert.Len(t, r.TLS.PeerCertificates, 1) {
			assert.Equal(t, token.BindingCertificate.Certificate[0], r.TLS.PeerCertificates[0].Raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"value":"test-value"}`))
		assert.NoError(t, err)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	credential := &checkedCredential{credential: tokenCredentialFunc(func(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
		assert.Equal(t, []string{vaultScope}, options.Scopes)
		assert.Equal(t, "tenant", options.TenantID)
		return token, nil
	})}
	client, err := azsecrets.NewClient(server.URL, credential, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			EnableMTLSPoP: true,
			Transport:     server.Client(),
			Retry:         policy.RetryOptions{MaxRetries: -1},
		},
		// The loopback server doesn't have a vault.azure.net hostname.
		DisableChallengeResourceVerification: true,
	})
	require.NoError(t, err)
	for range 2 {
		response, err := client.GetSecret(context.Background(), "test-secret", "", nil)
		require.NoError(t, err)
		require.NotNil(t, response.Value)
		assert.Equal(t, "test-value", *response.Value)
	}
	assert.Equal(t, int32(1), challenges.Load())
	assert.Equal(t, int32(3), requests.Load())
	assert.Equal(t, int32(1), credential.calls.Load())
}

func TestVerifyBuild(t *testing.T) {
	info := &debug.BuildInfo{}
	require.ErrorContains(t, verifyBuild(info), "azcore")
	localCore := &debug.Module{Path: "github.com/Azure/azure-sdk-for-go/sdk/azcore", Replace: &debug.Module{Path: "../../../azcore"}}
	localIdentity := &debug.Module{Path: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Replace: &debug.Module{Path: "../.."}}
	info.Deps = []*debug.Module{localCore}
	require.ErrorContains(t, verifyBuild(info), "azidentity")
	info.Deps = append(info.Deps, localIdentity)
	require.NoError(t, verifyBuild(info))
	localCore.Replace.Version = "(devel)"
	localIdentity.Replace.Version = "(devel)"
	require.NoError(t, verifyBuild(info))
	localIdentity.Replace = &debug.Module{Path: localIdentity.Path, Version: "v1.15.0"}
	require.ErrorContains(t, verifyBuild(info), "azidentity")
}
