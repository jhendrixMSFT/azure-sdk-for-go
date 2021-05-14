// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"golang.org/x/crypto/pkcs12"
)

// ClientCertificateCredentialOptions contain optional parameters that can be used when configuring a ClientCertificateCredential.
// All zero-value fields will be initialized with their default values.
type ClientCertificateCredentialOptions struct {
	// The password required to decrypt the private key.  Leave empty if there is no password.
	Password string
	// Set to true to include x5c header in client claims when acquiring a token to enable
	// SubjectName and Issuer based authentication for ClientCertificateCredential.
	SendCertificateChain bool
	// The host of the Azure Active Directory authority. The default is AzurePublicCloud.
	// Leave empty to allow overriding the value from the AZURE_AUTHORITY_HOST environment variable.
	AuthorityHost string
	// HTTPClient sets the transport for making HTTP requests
	// Leave this as nil to use the default HTTP transport
	HTTPClient azcore.Transport
	// Retry configures the built-in retry policy behavior
	Retry azcore.RetryOptions
	// Telemetry configures the built-in telemetry policy behavior
	Telemetry azcore.TelemetryOptions
	// Logging configures the built-in logging policy behavior.
	Logging azcore.LogOptions
}

// ClientCertificateCredential enables authentication of a service principal to Azure Active Directory using a certificate that is assigned to its App Registration. More information
// on how to configure certificate authentication can be found here:
// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials#register-your-certificate-with-azure-ad
type ClientCertificateCredential struct {
	client confidential.Client
}

// NewClientCertificateCredential creates an instance of ClientCertificateCredential with the details needed to authenticate against Azure Active Directory with the specified certificate.
// tenantID: The Azure Active Directory tenant (directory) ID of the service principal.
// clientID: The client (application) ID of the service principal.
// certificatePath: The path to the client certificate used to authenticate the client.  Supported formats are PEM and PFX.
// options: ClientCertificateCredentialOptions that can be used to provide additional configurations for the credential, such as the certificate password.
func NewClientCertificateCredential(tenantID string, clientID string, certificatePath string, options *ClientCertificateCredentialOptions) (*ClientCertificateCredential, error) {
	if !validTenantID(tenantID) {
		return nil, newCredentialUnavailableError("Client Certificate Credential", tenantIDValidationErr)
	}
	_, err := os.Stat(certificatePath)
	if err != nil {
		credErr := newCredentialUnavailableError("Client Certificate Credential", "Certificate file not found in path: "+certificatePath)
		logCredentialError(credErr.CredentialUnavailable(), credErr)
		return nil, credErr
	}
	certData, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		credErr := newCredentialUnavailableError("Client Certificate Credential", err.Error())
		logCredentialError(credErr.CredentialUnavailable(), credErr)
		return nil, credErr
	}
	if options == nil {
		options = &ClientCertificateCredentialOptions{}
	}
	var cert *certContents
	certificatePath = strings.ToUpper(certificatePath)
	if strings.HasSuffix(certificatePath, ".PEM") {
		cert, err = extractFromPEMFile(certData, options.Password, options.SendCertificateChain)
	} else if strings.HasSuffix(certificatePath, ".PFX") {
		cert, err = extractFromPFXFile(certData, options.Password, options.SendCertificateChain)
	} else {
		err = errors.New("only PEM and PFX files are supported")
	}
	if err != nil {
		credErr := newCredentialUnavailableError("Client Certificate Credential", err.Error())
		logCredentialError(credErr.CredentialUnavailable(), credErr)
		return nil, credErr
	}
	authorityHost, err := setAuthorityHost(options.AuthorityHost)
	if err != nil {
		return nil, err
	}
	pipeline := newDefaultPipeline(pipelineOptions{HTTPClient: options.HTTPClient, Retry: options.Retry, Telemetry: options.Telemetry, Logging: options.Logging})
	confOpts := []confidential.Option{
		confidential.WithAuthority(azcore.JoinPaths(authorityHost, tenantID)),
		confidential.WithHTTPClient(pipelineAdapter{pl: pipeline}),
	}
	if options.SendCertificateChain {
		confOpts = append(confOpts, confidential.WithX5C())
	}
	c, err := confidential.New(clientID, confidential.NewCredFromCert(cert.ce, cert.pk),
		confOpts...)
	if err != nil {
		return nil, err
	}
	return &ClientCertificateCredential{client: c}, nil
}

// contains decoded cert contents we care about
type certContents struct {
	ce                 *x509.Certificate
	pk                 *rsa.PrivateKey
	publicCertificates []string
}

func newCertContents(blocks []*pem.Block, fromPEM bool, sendCertificateChain bool) (*certContents, error) {
	cc := certContents{}
	// first extract the private key
	for _, block := range blocks {
		if block.Type == "PRIVATE KEY" {
			var key interface{}
			var err error
			if fromPEM {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			} else {
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}
			if err != nil {
				return nil, err
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("unexpected private key type %T", key)
			}
			cc.pk = rsaKey
			break
		}
	}
	if cc.pk == nil {
		return nil, errors.New("missing private key")
	}
	// now find the certificate with the matching public key of our private key
	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				// keep looking
				continue
			}
			if cc.pk.E != certKey.E || cc.pk.N.Cmp(certKey.N) != 0 {
				// keep looking
				continue
			}
			// found a match
			cc.ce = cert
			break
		}
	}
	if cc.ce == nil {
		return nil, errors.New("missing certificate")
	}
	// now find all the public certificates to send in the x5c header
	if sendCertificateChain {
		for _, block := range blocks {
			if block.Type == "CERTIFICATE" {
				cc.publicCertificates = append(cc.publicCertificates, base64.StdEncoding.EncodeToString(block.Bytes))
			}
		}
	}
	return &cc, nil
}

func extractFromPEMFile(certData []byte, password string, sendCertificateChain bool) (*certContents, error) {
	// TODO: wire up support for password
	blocks := []*pem.Block{}
	// read all of the PEM blocks
	for {
		var block *pem.Block
		block, certData = pem.Decode(certData)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, errors.New("didn't find any blocks in PEM file")
	}
	return newCertContents(blocks, true, sendCertificateChain)
}

func extractFromPFXFile(certData []byte, password string, sendCertificateChain bool) (*certContents, error) {
	// convert PFX binary data to PEM blocks
	blocks, err := pkcs12.ToPEM(certData, password)
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, errors.New("didn't find any blocks in PFX file")
	}
	return newCertContents(blocks, false, sendCertificateChain)
}

// GetToken obtains a token from Azure Active Directory, using the certificate in the file path.
// scopes: The list of scopes for which the token will have access.
// ctx: controlling the request lifetime.
// Returns an AccessToken which can be used to authenticate service client calls.
func (c *ClientCertificateCredential) GetToken(ctx context.Context, opts azcore.TokenRequestOptions) (*azcore.AccessToken, error) {
	// check for cached token
	tk, err := c.client.AcquireTokenSilent(ctx, opts.Scopes)
	if err == nil {
		return &azcore.AccessToken{
			Token:     tk.AccessToken,
			ExpiresOn: tk.ExpiresOn,
		}, err
	}
	// request token
	tk, err = c.client.AcquireTokenByCredential(ctx, opts.Scopes)
	if err != nil {
		addGetTokenFailureLogs("Client Certificate Credential", err, true)
		return nil, err
	}
	logGetTokenSuccess(c, opts)
	return &azcore.AccessToken{
		Token:     tk.AccessToken,
		ExpiresOn: tk.ExpiresOn,
	}, err
}

// AuthenticationPolicy implements the azcore.Credential interface on ClientCertificateCredential.
func (c *ClientCertificateCredential) AuthenticationPolicy(options azcore.AuthenticationPolicyOptions) azcore.Policy {
	return newBearerTokenPolicy(c, options)
}
