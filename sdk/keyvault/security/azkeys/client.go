// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azkeys

import (
	"context"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

type KeyClient struct {
	u *url.URL
	p azcore.Pipeline
}

func NewKeyClient(endpoint string, cred azcore.Credential, options azcore.PipelineOptions) (KeyClient, error) {
	if options.HTTPClient == nil {
		options.HTTPClient = azcore.DefaultHTTPClientPolicy()
	}
	p := azcore.NewPipeline(azcore.NewTelemetryPolicy(options.Telemetry),
		azcore.NewUniqueRequestIDPolicy(),
		azcore.NewRetryPolicy(options.Retry),
		cred,
		azcore.NewBodyDownloadPolicy(),
		azcore.NewRequestLogPolicy(options.LogOptions),
		options.HTTPClient)
	return NewKeyClientWithPipeline(endpoint, p)
}

func NewKeyClientWithPipeline(endpoint string, p azcore.Pipeline) (KeyClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return KeyClient{}, err
	}
	return KeyClient{u: u, p: p}, nil
}

func (c KeyClient) ServiceVersion() string {
	// this is a method instead of a package-level const to handle the case of composite services
	return "2017-07-29"
}

// StartDelete deletes a key of any type with the specified name from storage in Azure Key Vault.
func (c KeyClient) StartDelete(ctx context.Context, name string) (*DeleteOperation, error) {
	return nil, nil
}

// DeleteOperation creates a new DeleteOperation from the specified ID.
// The ID must come from a previous call to DeleteOperation.ID().
func (c KeyClient) DeleteOperation(id string) *DeleteOperation {
	return &DeleteOperation{}
}
