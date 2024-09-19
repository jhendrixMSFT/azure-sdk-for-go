//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package fake_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azadmin/backup"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azadmin/backup/fake"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	fakeServer := fake.Server{
		BeginFullBackup: func(ctx context.Context, azureStorageBlobContainerURI backup.SASTokenParameters, options *backup.BeginFullBackupOptions) (resp azfake.PollerResponder[backup.FullBackupResponse], errResp azfake.ErrorResponder) {
			resp.AddNonTerminalResponse(http.StatusAccepted, nil)
			resp.AddNonTerminalResponse(http.StatusAccepted, nil)

			backupResp := backup.FullBackupResponse{}
			backupResp.AzureStorageBlobContainerURI = to.Ptr("testing1")
			backupResp.Status = to.Ptr("Succeeded")

			resp.SetTerminalResponse(http.StatusOK, backupResp, nil)

			return
		},
	}

	// now create the corresponding client, connecting the fake server via the client options
	client, err := backup.NewClient("https://fake-vault.vault.azure.net", &azfake.TokenCredential{}, &backup.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: fake.NewServerTransport(&fakeServer),
		},
	})
	require.NoError(t, err)

	poller, err := client.BeginFullBackup(context.TODO(), backup.SASTokenParameters{StorageResourceURI: to.Ptr("testing")}, nil)
	require.NoError(t, err)

	resp, err := poller.PollUntilDone(context.TODO(), &runtime.PollUntilDoneOptions{
		Frequency: time.Second,
	})
	require.NoError(t, err)
	_ = resp

}
