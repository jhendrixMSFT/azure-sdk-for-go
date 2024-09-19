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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets/fake"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	fakeServer := fake.Server{
		GetSecret: func(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (resp azfake.Responder[azsecrets.GetSecretResponse], errResp azfake.ErrorResponder) {
			id := azsecrets.ID(fmt.Sprintf("https://fake-vault.vault.azure.net/secrets/%s/%s", name, version))
			kvResp := azsecrets.GetSecretResponse{Secret: azsecrets.Secret{
				ID: &id,
			}}
			resp.SetResponse(http.StatusOK, kvResp, nil)
			return
		},
	}

	client, err := azsecrets.NewClient("https://fake-vault.vault.azure.net", &azfake.TokenCredential{}, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: fake.NewServerTransport(&fakeServer),
		},
	})
	require.NoError(t, err)

	secretName := "secretName"
	version := "123"
	resp, err := client.GetSecret(context.TODO(), secretName, version, nil)
	require.NoError(t, err)

	require.Equal(t, secretName, resp.ID.Name())
	require.Equal(t, version, resp.ID.Version())
}
