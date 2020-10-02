// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package armappconfiguration

import (
	original "github.com/Azure/azure-sdk-for-go/sdk/arm/appconfiguration/2019-10-01/armappconfiguration"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// ClientOptions contains configuration settings for the default client's pipeline.
type ClientOptions = original.ClientOptions

// DefaultClientOptions creates a ClientOptions type initialized with default values.
func DefaultClientOptions() ClientOptions {
	return original.DefaultClientOptions()
}

type Client = original.Client

// DefaultEndpoint is the default service endpoint.
const DefaultEndpoint = original.DefaultEndpoint

// NewDefaultClient creates an instance of the Client type using the DefaultEndpoint.
func NewDefaultClient(cred azcore.Credential, options *ClientOptions) *Client {
	return original.NewClient(DefaultEndpoint, cred, options)
}

// NewClient creates an instance of the Client type with the specified endpoint.
func NewClient(endpoint string, cred azcore.Credential, options *ClientOptions) *Client {
	return original.NewClient(endpoint, cred, options)
}

// NewClientWithPipeline creates an instance of the Client type with the specified endpoint and pipeline.
func NewClientWithPipeline(endpoint string, p azcore.Pipeline) *Client {
	return original.NewClientWithPipeline(endpoint, p)
}
