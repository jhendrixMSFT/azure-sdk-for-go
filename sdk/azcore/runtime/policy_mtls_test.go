// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMTLSPoPResourcePipeline(t *testing.T) {
	var calls atomic.Int32
	var cert tls.Certificate
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "mtls_pop "+tokenValue, r.Header.Get("Authorization"))
		assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
		assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
		assert.Len(t, r.TLS.PeerCertificates, 1)
		if len(r.TLS.PeerCertificates) == 1 {
			assert.Equal(t, cert.Certificate[0], r.TLS.PeerCertificates[0].Raw)
		}
		if calls.Add(1) == 1 {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_claims", claims="e30="`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()
	cert = server.TLS.Certificates[0]
	var acquisitions atomic.Int32
	cred := mockCredential{getTokenImpl: func(_ context.Context, opts policy.TokenRequestOptions) (exported.AccessToken, error) {
		assert.True(t, opts.EnableMTLSPoP)
		assert.True(t, opts.EnableCAE)
		assert.Equal(t, []string{scope}, opts.Scopes)
		if acquisitions.Add(1) == 2 {
			assert.Equal(t, "{}", opts.Claims)
		}
		return exported.AccessToken{Token: tokenValue, ExpiresOn: time.Now().Add(time.Hour), BindingCertificate: &cert}, nil
	}}
	base := server.Client()
	tr, ok := base.Transport.(*http.Transport)
	require.True(t, ok)
	p := NewPipeline("test", "v1.0.0", PipelineOptions{
		PerRetry: []policy.Policy{NewBearerTokenPolicy(cred, []string{scope}, nil)},
	}, &policy.ClientOptions{EnableMTLSPoP: true, Transport: base})
	req, err := NewRequest(context.Background(), http.MethodGet, server.URL)
	require.NoError(t, err)
	resp, err := p.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), acquisitions.Load())
	assert.Nil(t, tr.TLSClientConfig.GetClientCertificate, "the caller's transport must not be modified")

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			req, err := NewRequest(context.Background(), http.MethodGet, server.URL)
			assert.NoError(t, err)
			if err != nil {
				return
			}
			resp, err := p.Do(req)
			assert.NoError(t, err)
			if resp != nil {
				assert.NoError(t, resp.Body.Close())
			}
		})
	}
	wg.Wait()
	assert.Equal(t, int32(2), acquisitions.Load(), "bound tokens should be cached")
}

func TestMTLSPoPTokenRenewal(t *testing.T) {
	var calls atomic.Int32
	var certs [2]tls.Certificate
	tokens := [2]string{tokenValue, "renewed-token"}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		index := 0
		if call > 1 {
			index = 1
		}
		assert.Equal(t, "mtls_pop "+tokens[index], r.Header.Get("Authorization"))
		assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
		assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
		if assert.Len(t, r.TLS.PeerCertificates, 1) {
			assert.Equal(t, certs[index].Certificate[0], r.TLS.PeerCertificates[0].Raw,
				"renewal must not reuse a connection authenticated with the old certificate")
		}
		if call == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	certs[0] = server.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(certs[0].Certificate[0])
	require.NoError(t, err)
	leaf.SerialNumber = new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, certs[0].PrivateKey)
	require.NoError(t, err)
	certs[1] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: certs[0].PrivateKey}

	var acquisitions int
	auth := NewBearerTokenPolicy(mockCredential{getTokenImpl: func(_ context.Context, opts policy.TokenRequestOptions) (exported.AccessToken, error) {
		assert.True(t, opts.EnableMTLSPoP)
		assert.Equal(t, []string{scope}, opts.Scopes)
		index := 0
		if acquisitions > 0 {
			index = 1
		}
		acquisitions++
		return exported.AccessToken{
			Token: tokens[index], ExpiresOn: time.Now().Add(time.Hour), BindingCertificate: &certs[index],
		}, nil
	}}, []string{scope}, nil)
	p := NewPipeline("test", "v1.0.0", PipelineOptions{
		PerRetry: []policy.Policy{auth},
	}, &policy.ClientOptions{
		EnableMTLSPoP: true, Transport: server.Client(),
		Retry: policy.RetryOptions{MaxRetries: 1, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond},
	})
	for i := range 3 {
		if i == 1 {
			auth.mtlsResource.Expire()
		}
		req, err := NewRequest(context.Background(), http.MethodGet, server.URL)
		require.NoError(t, err)
		resp, err := p.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	assert.Equal(t, 2, acquisitions, "the retry and subsequent request must reuse the renewed bound token")
	assert.Equal(t, int32(4), calls.Load(), "three successful reads and one retried 503")
}

func TestMTLSPoPChallengeAuthentication(t *testing.T) {
	for _, bound := range []bool{true, false} {
		name := "bound token"
		if !bound {
			name = "unbound token"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			var cert tls.Certificate
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, uint16(tls.VersionTLS12), r.TLS.Version)
				if requests.Add(1) == 1 {
					assert.Empty(t, r.Header.Get("Authorization"))
					assert.Empty(t, r.Header.Get("x-ms-tokenboundauth"))
					assert.Empty(t, r.TLS.PeerCertificates, "the challenge must not use a caller-configured certificate")
					w.Header().Set("WWW-Authenticate", `Bearer resource="https://example.com"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				assert.Equal(t, "mtls_pop "+tokenValue, r.Header.Get("Authorization"))
				assert.Equal(t, "true", r.Header.Get("x-ms-tokenboundauth"))
				if assert.Len(t, r.TLS.PeerCertificates, 1) {
					assert.Equal(t, cert.Certificate[0], r.TLS.PeerCertificates[0].Raw)
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
			server.StartTLS()
			defer server.Close()
			cert = server.TLS.Certificates[0]
			base := server.Client()
			tr, ok := base.Transport.(*http.Transport)
			require.True(t, ok)
			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
			tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &cert, nil
			}
			var acquisitions int
			cred := mockCredential{getTokenImpl: func(_ context.Context, opts policy.TokenRequestOptions) (exported.AccessToken, error) {
				acquisitions++
				assert.True(t, opts.EnableMTLSPoP)
				assert.True(t, opts.EnableCAE)
				assert.Equal(t, []string{scope}, opts.Scopes)
				token := exported.AccessToken{Token: tokenValue, ExpiresOn: time.Now().Add(time.Hour)}
				if bound {
					token.BindingCertificate = &cert
				}
				return token, nil
			}}
			challenged := false
			p := NewPipeline("test", "v1.0.0", PipelineOptions{
				PerRetry: []policy.Policy{NewBearerTokenPolicy(cred, nil, &policy.BearerTokenOptions{
					AuthorizationHandler: policy.AuthorizationHandler{
						OnRequest: func(_ *policy.Request, authNZ func(policy.TokenRequestOptions) error) error {
							if !challenged {
								return nil
							}
							return authNZ(policy.TokenRequestOptions{Scopes: []string{scope}})
						},
						OnChallenge: func(_ *policy.Request, _ *http.Response, authNZ func(policy.TokenRequestOptions) error) error {
							challenged = true
							return authNZ(policy.TokenRequestOptions{Scopes: []string{scope}})
						},
					},
				})},
			}, &policy.ClientOptions{EnableMTLSPoP: true, Transport: base})
			for range 2 {
				req, err := NewRequest(context.Background(), http.MethodGet, server.URL)
				require.NoError(t, err)
				resp, err := p.Do(req)
				if !bound {
					require.ErrorContains(t, err, "no binding certificate")
					assert.Equal(t, int32(1), requests.Load(), "an unbound token must never reach the resource")
					assert.Equal(t, 1, acquisitions)
					return
				}
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
			assert.Equal(t, int32(3), requests.Load(), "one challenge followed by two authenticated requests")
			assert.Equal(t, 1, acquisitions, "the bound token should be cached")
			assert.Len(t, tr.TLSClientConfig.Certificates, 1, "the caller's transport must not be modified")
		})
	}
}

func TestMTLSPoPRejectsAuthenticationWithoutCertificate(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	for _, headers := range []http.Header{
		{"Authorization": {"Bearer " + tokenValue}},
		{"Authorization": {"mtls_pop " + tokenValue}},
		{"Authorization": {""}},
		{"Authorization": {"", "Bearer " + tokenValue}},
		{"authorization": {"Bearer " + tokenValue}},
		{"x-ms-tokenboundauth": {"true"}},
	} {
		p := NewPipeline("test", "v1.0.0", PipelineOptions{}, &policy.ClientOptions{
			EnableMTLSPoP: true, Transport: server.Client(),
		})
		req, err := NewRequest(context.Background(), http.MethodGet, server.URL)
		require.NoError(t, err)
		req.Raw().Header = headers
		resp, err := p.Do(req)
		require.ErrorContains(t, err, "binding certificate")
		require.Nil(t, resp)
	}
	assert.Zero(t, requests.Load())
}

func TestMTLSPoPRejectsDowngrade(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enabled, bound bool
		message        string
	}{
		{name: "unbound response", enabled: true, message: "no binding certificate"},
		{name: "unexpected bound response", bound: true, message: "bearer authentication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := (*tls.Certificate)(nil)
			if tc.bound {
				cert = &tls.Certificate{}
			}
			cred := mockCredential{getTokenImpl: func(context.Context, policy.TokenRequestOptions) (exported.AccessToken, error) {
				return exported.AccessToken{Token: tokenValue, ExpiresOn: time.Now().Add(time.Hour), BindingCertificate: cert}, nil
			}}
			srv, close := mock.NewTLSServer()
			defer close()
			p := NewPipeline("test", "v1.0.0", PipelineOptions{
				PerRetry: []policy.Policy{NewBearerTokenPolicy(cred, []string{scope}, nil)},
			}, &policy.ClientOptions{EnableMTLSPoP: tc.enabled, Transport: srv})
			req, err := NewRequest(context.Background(), http.MethodGet, srv.URL())
			require.NoError(t, err)
			resp, err := p.Do(req)
			require.ErrorContains(t, err, tc.message)
			require.Nil(t, resp)
		})
	}
}

func TestMTLSPoPSeparateTokenCaches(t *testing.T) {
	var bearer, bound int
	b := NewBearerTokenPolicy(mockCredential{getTokenImpl: func(_ context.Context, opts policy.TokenRequestOptions) (exported.AccessToken, error) {
		tk := exported.AccessToken{Token: tokenValue, ExpiresOn: time.Now().Add(time.Hour)}
		if opts.EnableMTLSPoP {
			bound++
			tk.BindingCertificate = &tls.Certificate{}
		} else {
			bearer++
		}
		return tk, nil
	}}, []string{scope}, nil)
	for _, enabled := range []bool{false, true, false, true} {
		req, err := NewRequest(context.Background(), http.MethodGet, "https://example.com")
		require.NoError(t, err)
		req.SetOperationValue(mtlsRequest{enabled: enabled})
		require.NoError(t, b.authenticateAndAuthorize(req)(policy.TokenRequestOptions{Scopes: []string{scope}}))
	}
	assert.Equal(t, 1, bearer)
	assert.Equal(t, 1, bound)
}

func TestMTLSPoPTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := server.TLS.Certificates[0]
	base := server.Client()
	baseTransport, ok := base.Transport.(*http.Transport)
	require.True(t, ok)
	sessionCache := tls.NewLRUClientSessionCache(1)
	baseTransport.TLSClientConfig.ClientSessionCache = sessionCache
	p := &mtlsPolicy{base: base}
	client, err := p.client(&cert)
	require.NoError(t, err)
	t.Cleanup(client.CloseIdleConnections)
	cached, err := p.client(&cert)
	require.NoError(t, err)
	require.Same(t, client, cached)
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	got, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{AcceptableCAs: [][]byte{[]byte("unrelated CA")}})
	require.NoError(t, err)
	assert.Same(t, &cert, got, "CA hints must not filter out the binding certificate")
	assert.Equal(t, tls.RenegotiateOnceAsClient, tr.TLSClientConfig.Renegotiation)
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MaxVersion)
	assert.Nil(t, tr.TLSClientConfig.ClientSessionCache, "session resumption must not cross certificate boundaries")
	assert.Same(t, sessionCache, baseTransport.TLSClientConfig.ClientSessionCache)
	assert.Error(t, client.CheckRedirect(nil, nil))
	challenge, err := p.client(nil)
	require.NoError(t, err)
	t.Cleanup(challenge.CloseIdleConnections)
	assert.NotSame(t, client, challenge, "a challenge must not reuse a certificate-authenticated connection")
	challengeTransport, ok := challenge.Transport.(*http.Transport)
	require.True(t, ok)
	got, err = challengeTransport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got.Certificate)
	assert.Nil(t, got.PrivateKey)
	assert.Nil(t, challengeTransport.TLSClientConfig.ClientSessionCache)
	cached, err = p.client(nil)
	require.NoError(t, err)
	assert.Same(t, challenge, cached)
	for range 10 {
		copy := cert
		rotated, err := p.client(&copy)
		require.NoError(t, err)
		t.Cleanup(rotated.CloseIdleConnections)
		assert.NotSame(t, client, rotated, "rotation requires a separate connection pool")
	}
	assert.Len(t, p.clients, 8)
}

func TestMTLSPoPUnsupportedConfiguration(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: struct{}{}}
	srv, close := mock.NewServer()
	defer close()
	for _, tc := range []struct {
		name    string
		base    policy.Transporter
		message string
	}{
		{name: "custom transporter", base: srv, message: "*http.Client"},
		{name: "custom round tripper", base: &http.Client{Transport: mtlsRoundTripper{}}, message: "*http.Transport"},
		{name: "TLS dialer", base: &http.Client{Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected call") },
		}}, message: "custom TLS dialing"},
		{name: "TLS 1.3 only", base: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}, message: "TLS 1.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, binding := range []*tls.Certificate{nil, cert} {
				_, err := (&mtlsPolicy{base: tc.base}).client(binding)
				require.ErrorContains(t, err, tc.message)
			}
		})
	}
	p := NewPipeline("test", "v1.0.0", PipelineOptions{}, &policy.ClientOptions{
		EnableMTLSPoP: true, InsecureAllowCredentialWithHTTP: true,
	})
	req, err := NewRequest(context.Background(), http.MethodGet, "http://example.com")
	require.NoError(t, err)
	_, err = p.Do(req)
	require.ErrorContains(t, err, "HTTPS")
	_, err = (&mtlsPolicy{}).client(&tls.Certificate{})
	require.ErrorContains(t, err, "private key")
}

type mtlsRoundTripper struct{}

func (mtlsRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func TestMTLSPoPRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	cert := server.TLS.Certificates[0]
	p := &mtlsPolicy{base: server.Client()}
	for _, binding := range []*tls.Certificate{nil, &cert} {
		client, err := p.client(binding)
		require.NoError(t, err)
		defer client.CloseIdleConnections()
		resp, err := client.Get(server.URL)
		require.ErrorContains(t, err, "redirects")
		if resp != nil {
			require.NoError(t, resp.Body.Close())
		}
	}
	assert.False(t, redirected.Load())
}

func TestMTLSPoPRespectsServerTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := server.TLS.Certificates[0]
	p := &mtlsPolicy{base: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()},
	}}}
	for _, binding := range []*tls.Certificate{nil, &cert} {
		client, err := p.client(binding)
		require.NoError(t, err)
		defer client.CloseIdleConnections()
		_, err = client.Get(server.URL)
		var verificationError *tls.CertificateVerificationError
		require.ErrorAs(t, err, &verificationError)
	}
}

func TestMTLSPoPCertificateExpiration(t *testing.T) {
	now := time.Now()
	req, err := NewRequest(context.Background(), http.MethodGet, "https://example.com")
	require.NoError(t, err)
	for _, lifetime := range []time.Duration{time.Minute, 2 * time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			tk := exported.AccessToken{
				Token: tokenValue, ExpiresOn: now.Add(time.Hour), RefreshOn: now.Add(30 * time.Minute),
				BindingCertificate: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(lifetime)}},
			}
			state := acquiringResourceState{
				req: req,
				p: &BearerTokenPolicy{cred: mockCredential{getTokenImpl: func(context.Context, policy.TokenRequestOptions) (exported.AccessToken, error) {
					return tk, nil
				}}},
			}
			got, expiration, err := acquire(state)
			require.NoError(t, err)
			expected := tk.ExpiresOn
			if lifetime < time.Hour {
				expected = tk.BindingCertificate.Leaf.NotAfter
			}
			assert.Equal(t, expected, expiration)
			assert.Equal(t, tk.ExpiresOn, got.ExpiresOn)
			assert.Equal(t, lifetime < 5*time.Minute, shouldRefresh(got, state))
		})
	}
}
