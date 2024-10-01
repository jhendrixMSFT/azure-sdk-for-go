//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package fake_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates/fake"
	"github.com/stretchr/testify/require"
)

var (
	version  = "123"
	certName = "certName"
)

func getServer() fake.Server {
	return fake.Server{
		CreateCertificate: func(ctx context.Context, certificateName string, parameters azcertificates.CreateCertificateParameters, options *azcertificates.CreateCertificateOptions) (resp azfake.Responder[azcertificates.CreateCertificateResponse], errResp azfake.ErrorResponder) {
			kvResp := azcertificates.CreateCertificateResponse{
				CertificateOperation: azcertificates.CertificateOperation{
					ID: to.Ptr(azcertificates.ID(fmt.Sprintf("https://fake-vault.vault.azure.net/certificates/%s/%s", certificateName, "pending"))),
				},
			}
			resp.SetResponse(http.StatusAccepted, kvResp, nil)
			return
		},
		GetCertificate: func(ctx context.Context, certificateName string, version string, options *azcertificates.GetCertificateOptions) (resp azfake.Responder[azcertificates.GetCertificateResponse], errResp azfake.ErrorResponder) {
			kvResp := azcertificates.GetCertificateResponse{
				Certificate: azcertificates.Certificate{
					ID: to.Ptr(azcertificates.ID(fmt.Sprintf("https://fake-vault.vault.azure.net/certificates/%s/%s", certificateName, version))),
				},
			}
			resp.SetResponse(http.StatusOK, kvResp, nil)
			return
		},
		GetCertificateOperation: func(ctx context.Context, certificateName string, options *azcertificates.GetCertificateOperationOptions) (resp azfake.Responder[azcertificates.GetCertificateOperationResponse], errResp azfake.ErrorResponder) {
			kvResp := azcertificates.GetCertificateOperationResponse{
				CertificateOperation: azcertificates.CertificateOperation{
					ID: to.Ptr(azcertificates.ID(fmt.Sprintf("https://fake-vault.vault.azure.net/certificates/%s/%s", certificateName, "pending"))),
				},
			}
			resp.SetResponse(http.StatusOK, kvResp, nil)
			return
		},
		UpdateCertificate: func(ctx context.Context, certificateName string, certificateVersion string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (resp azfake.Responder[azcertificates.UpdateCertificateResponse], errResp azfake.ErrorResponder) {
			kvResp := azcertificates.UpdateCertificateResponse{
				Certificate: azcertificates.Certificate{
					ID: to.Ptr(azcertificates.ID(fmt.Sprintf("https://fake-vault.vault.azure.net/certificates/%s/%s", certificateName, version))),
					Attributes: &azcertificates.CertificateAttributes{
						Expires: parameters.CertificateAttributes.Expires,
					},
				},
			}
			resp.SetResponse(http.StatusOK, kvResp, nil)
			return
		},
	}
}

func TestServer(t *testing.T) {
	fakeServer := getServer()

	client, err := azcertificates.NewClient("https://fake-vault.vault.azure.net", &azfake.TokenCredential{}, &azcertificates.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: fake.NewServerTransport(&fakeServer),
		},
	})
	require.NoError(t, err)

	// create certificate
	createResp, err := client.CreateCertificate(context.Background(), certName, azcertificates.CreateCertificateParameters{}, nil)
	require.NoError(t, err)
	require.Equal(t, certName, createResp.ID.Name())
	require.Equal(t, "pending", createResp.ID.Version())

	// get certificate operation
	getOpResp, err := client.GetCertificateOperation(context.Background(), certName, nil)
	require.NoError(t, err)
	require.Equal(t, certName, getOpResp.ID.Name())
	require.Equal(t, "pending", getOpResp.ID.Version())

	// get certificate
	getResp, err := client.GetCertificate(context.Background(), certName, "", nil)
	require.NoError(t, err)
	require.Equal(t, certName, getResp.ID.Name())
	require.Empty(t, getResp.ID.Version())

	// TODO figure out bearer token policy interfering with fakes
	// update certificate
	updateParams := azcertificates.UpdateCertificateParameters{
		CertificateAttributes: &azcertificates.CertificateAttributes{
			Expires: to.Ptr(time.Date(2030, 1, 1, 1, 1, 1, 0, time.UTC)),
		},
	}
	updateResp, err := client.UpdateCertificate(context.Background(), certName, "123", updateParams, nil)
	require.NoError(t, err)
	require.Equal(t, certName, updateResp.ID.Name())
	require.Equal(t, version, updateResp.ID.Version())
}
