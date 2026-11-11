// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const vaultScope = "https://vault.azure.net/.default"

type configuration struct {
	vaultURL, secretName           string
	clientID, objectID, resourceID string
	timeout                        time.Duration
	attestation                    bool
}

func main() {
	var cfg configuration
	flag.StringVar(&cfg.vaultURL, "vault-url", "", "HTTPS URL of an mTLS PoP-enabled public Azure Key Vault (required)")
	flag.StringVar(&cfg.secretName, "secret-name", "", "Existing secret the managed identity can read (required)")
	flag.StringVar(&cfg.clientID, "client-id", "", "User-assigned identity client ID; omit all identity flags for system-assigned")
	flag.StringVar(&cfg.objectID, "object-id", "", "User-assigned identity object ID (mutually exclusive with other identity flags)")
	flag.StringVar(&cfg.resourceID, "resource-id", "", "User-assigned identity resource ID (mutually exclusive with other identity flags)")
	flag.BoolVar(&cfg.attestation, "attestation", false, "Request KeyGuard key attestation (requires AttestationClientLib.dll and the x64 Visual C++ runtime)")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Minute, "Overall test timeout")
	flag.Parse()
	if err := run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg configuration) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("Go build information is unavailable")
	}
	if err := verifyBuild(info); err != nil {
		return err
	}
	// Refuse source overrides instead of changing the caller's environment or testing another service.
	for _, name := range []string{
		"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT",
		"IMDS_ENDPOINT", "MSI_ENDPOINT", "MSI_SECRET", "AZURE_POD_IDENTITY_AUTHORITY_HOST",
		"MSAL_MI_DISABLE_IMDS_V2",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("%s is set; run from a clean Azure VM environment using native IMDS", name)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	credential, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ID: cfg.identity(), EnableAttestation: cfg.attestation,
	})
	if err != nil {
		return fmt.Errorf("creating ManagedIdentityCredential: %w", err)
	}
	bearer, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{vaultScope}})
	if err != nil {
		return fmt.Errorf("initial bearer acquisition: %w", err)
	}
	if err := validateBearer(bearer); err != nil {
		return err
	}
	fmt.Println("PASS: ordinary bearer acquisition returns no binding certificate")

	bound, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{vaultScope}, EnableMTLSPoP: true})
	if err != nil {
		return fmt.Errorf("mTLS PoP acquisition (requires Windows, Credential Guard/KeyGuard, and IMDSv2): %w", err)
	}
	thumbprint, err := validateBound(bound, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("PASS: bound token cnf.x5t#S256 matches certificate %s; token expires %s\n",
		thumbprint, bound.ExpiresOn.UTC().Format(time.RFC3339))

	target := strings.TrimRight(cfg.vaultURL, "/") + "/secrets/" + url.PathEscape(cfg.secretName) + "?api-version=7.4"
	if err := verifyResource(ctx, target, bound); err != nil {
		return err
	}
	fmt.Println("PASS: direct mTLS resource request succeeds; same token without certificate returns MissingClientCertificate")

	bearer, err = credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{vaultScope}})
	if err != nil {
		return fmt.Errorf("bearer acquisition after mTLS PoP: %w", err)
	}
	if err := validateBearer(bearer); err != nil {
		return err
	}
	fmt.Println("PASS: bearer acquisition remains unbound after mTLS PoP acquisition")

	if err := verifySDK(ctx, cfg, credential); err != nil {
		return fmt.Errorf("automatic SDK mTLS PoP: %w", err)
	}
	fmt.Println("PASS: Key Vault SDK reads secret twice with ClientOptions.EnableMTLSPoP")
	fmt.Println("PASS: all mTLS PoP smoke checks")
	return nil
}

func (c configuration) validate() error {
	u, err := url.Parse(c.vaultURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("vault-url must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if c.secretName == "" || strings.ContainsAny(c.secretName, "/\\?#") || c.timeout <= 0 {
		return errors.New("secret-name must be a nonempty secret name and timeout must be positive")
	}
	selectors := 0
	for _, id := range []string{c.clientID, c.objectID, c.resourceID} {
		if id != "" {
			selectors++
		}
	}
	if selectors > 1 {
		return errors.New("specify at most one of client-id, object-id, and resource-id")
	}
	return nil
}

func (c configuration) identity() azidentity.ManagedIDKind {
	switch {
	case c.clientID != "":
		return azidentity.ClientID(c.clientID)
	case c.objectID != "":
		return azidentity.ObjectID(c.objectID)
	case c.resourceID != "":
		return azidentity.ResourceID(c.resourceID)
	default:
		return nil
	}
}

func verifyBuild(info *debug.BuildInfo) error {
	for _, name := range []string{"azcore", "azidentity"} {
		path := "github.com/Azure/azure-sdk-for-go/sdk/" + name
		local := false
		for _, dep := range info.Deps {
			if dep.Path == path && dep.Replace != nil && dep.Replace.Path != "" &&
				(dep.Replace.Version == "" || dep.Replace.Version == "(devel)") {
				fmt.Printf("Using local %s: %s\n", name, dep.Replace.Path)
				local = true
				break
			}
		}
		if !local {
			return fmt.Errorf("%s must be replaced with this checkout; dependency replace directives aren't transitive", name)
		}
	}
	return nil
}

func validateBearer(token azcore.AccessToken) error {
	if token.Token == "" || !token.ExpiresOn.After(time.Now()) || token.BindingCertificate != nil {
		return errors.New("bearer acquisition must return a nonempty, unexpired token without a binding certificate")
	}
	return nil
}

func validateBound(token azcore.AccessToken, now time.Time) (string, error) {
	cert := token.BindingCertificate
	if token.Token == "" || !token.ExpiresOn.After(now) || cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return "", errors.New("mTLS PoP must return a nonempty, unexpired token and a binding certificate with a private key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("parsing binding certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return "", errors.New("binding certificate isn't currently valid")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return "", errors.New("binding private key doesn't implement crypto.Signer")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", fmt.Errorf("marshaling binding public key: %w", err)
	}
	if !bytes.Equal(publicKey, leaf.RawSubjectPublicKeyInfo) {
		return "", errors.New("binding private key doesn't match the leaf certificate")
	}
	parts := strings.Split(token.Token, ".")
	if len(parts) != 3 {
		return "", errors.New("bound access token isn't a three-part JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding bound token payload: %w", err)
	}
	var claims struct {
		Confirmation struct {
			Thumbprint string `json:"x5t#S256"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("decoding bound token claims: %w", err)
	}
	hash := sha256.Sum256(leaf.Raw)
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])
	if claims.Confirmation.Thumbprint != thumbprint {
		return "", errors.New("bound token cnf.x5t#S256 is missing or doesn't match the binding certificate")
	}
	return thumbprint, nil
}

func newResourceClient(cert *tls.Certificate, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs:       roots,
				MinVersion:    tls.VersionTLS12,
				MaxVersion:    tls.VersionTLS12,
				Renegotiation: tls.RenegotiateOnceAsClient,
				// Key Vault asks for the certificate after reading the authorization header.
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					if cert == nil {
						return &tls.Certificate{}, nil
					}
					return cert, nil
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects aren't permitted for mTLS PoP")
		},
	}
}

func resourceGET(ctx context.Context, client *http.Client, target, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "mtls_pop "+token)
	req.Header.Set("x-ms-tokenboundauth", "true")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading resource response: %w", err)
	}
	if len(body) > maxBody {
		return resp.StatusCode, nil, errors.New("resource response exceeds 1 MiB")
	}
	return resp.StatusCode, body, nil
}

func verifyResource(ctx context.Context, target string, token azcore.AccessToken) error {
	client := newResourceClient(token.BindingCertificate, nil)
	defer client.CloseIdleConnections()
	status, body, err := resourceGET(ctx, client, target, token.Token)
	if err != nil {
		return fmt.Errorf("direct bound resource request: %w", err)
	}
	if err := validateResourceResponse(status, body); err != nil {
		return fmt.Errorf("direct bound resource request: %w", err)
	}
	// A separate transport prevents the negative request from reusing an authenticated connection.
	withoutCert := newResourceClient(nil, nil)
	defer withoutCert.CloseIdleConnections()
	status, body, err = resourceGET(ctx, withoutCert, target, token.Token)
	if err != nil {
		return fmt.Errorf("missing-certificate request failed without an HTTP rejection; this isn't proof of binding: %w", err)
	}
	return validateRejection(status, body)
}

func validateResourceResponse(status int, body []byte) error {
	if status == http.StatusOK {
		return nil
	}
	// Only report error codes, never a secret value, error message, or raw response body.
	var response struct {
		Error struct {
			Code       string `json:"code"`
			InnerError struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("HTTP %d, want 200 (couldn't decode Key Vault error response; body omitted)", status)
	}
	if response.Error.Code == "" {
		return fmt.Errorf("HTTP %d, want 200 (no Key Vault error code in response; body omitted)", status)
	}
	return fmt.Errorf("HTTP %d, want 200 (Key Vault code %q, inner code %q; check vault opt-in, RBAC, network access, and secret name)",
		status, response.Error.Code, response.Error.InnerError.Code)
}

func validateRejection(status int, body []byte) error {
	if status < 400 || status >= 500 || !bytes.Contains(body, []byte("MissingClientCertificate")) {
		return fmt.Errorf("missing-certificate request: HTTP %d without the required 4xx/MissingClientCertificate rejection", status)
	}
	return nil
}

type checkedCredential struct {
	credential azcore.TokenCredential
	calls      atomic.Int32
}

func (c *checkedCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if !options.EnableMTLSPoP {
		return azcore.AccessToken{}, errors.New("SDK didn't propagate EnableMTLSPoP to the credential")
	}
	token, err := c.credential.GetToken(ctx, options)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	if _, err := validateBound(token, time.Now()); err != nil {
		return azcore.AccessToken{}, err
	}
	c.calls.Add(1)
	return token, nil
}

func verifySDK(ctx context.Context, cfg configuration, credential azcore.TokenCredential) error {
	checked := &checkedCredential{credential: credential}
	client, err := azsecrets.NewClient(cfg.vaultURL, checked, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			EnableMTLSPoP: true,
			Retry:         policy.RetryOptions{MaxRetries: -1},
		},
	})
	if err != nil {
		return err
	}
	for i := 1; i <= 2; i++ {
		if _, err := client.GetSecret(ctx, cfg.secretName, "", nil); err != nil {
			// Don't print the response body: it may contain a secret value.
			var response *azcore.ResponseError
			if errors.As(err, &response) {
				return fmt.Errorf("GetSecret #%d: HTTP %d, code %s", i, response.StatusCode, response.ErrorCode)
			}
			return fmt.Errorf("GetSecret #%d: %w", i, err)
		}
	}
	if checked.calls.Load() == 0 {
		return errors.New("SDK resource calls never requested a bound token")
	}
	return nil
}
