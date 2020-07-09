// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armcompute

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/internal/runtime"
)

const scope = "https://management.azure.com//.default"
const telemetryInfo = "azsdk-go-armcompute/<version>"

// ClientOptions contains configuration settings for the default client's pipeline.
type ClientOptions struct {
	// HTTPClient sets the transport for making HTTP requests.
	HTTPClient azcore.Transport
	// LogOptions configures the built-in request logging policy behavior.
	LogOptions azcore.RequestLogOptions
	// Retry configures the built-in retry policy behavior.
	Retry azcore.RetryOptions
	// Telemetry configures the built-in telemetry policy behavior.
	Telemetry azcore.TelemetryOptions
	// ApplicationID is an application-specific identification string used in telemetry.
	// It has a maximum length of 24 characters and must not contain any spaces.
	ApplicationID string
}

// DefaultClientOptions creates a ClientOptions type initialized with default values.
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		HTTPClient: azcore.DefaultHTTPClientTransport(),
		Retry:      azcore.DefaultRetryOptions(),
	}
}

func (c *ClientOptions) telemetryOptions() azcore.TelemetryOptions {
	t := telemetryInfo
	if c.ApplicationID != "" {
		a := strings.ReplaceAll(c.ApplicationID, " ", "/")
		if len(a) > 24 {
			a = a[:24]
		}
		t = fmt.Sprintf("%s %s", a, telemetryInfo)
	}
	if c.Telemetry.Value == "" {
		return azcore.TelemetryOptions{Value: t}
	}
	return azcore.TelemetryOptions{Value: fmt.Sprintf("%s %s", c.Telemetry.Value, t)}
}

// Client - Compute Client
type Client struct {
	u *url.URL
	p azcore.Pipeline
}

// DefaultEndpoint is the default service endpoint.
const DefaultEndpoint = "https://management.azure.com"

// NewDefaultClient creates an instance of the Client type using the DefaultEndpoint.
func NewDefaultClient(cred azcore.Credential, options *ClientOptions) (*Client, error) {
	return NewClient(DefaultEndpoint, cred, options)
}

// NewClient creates an instance of the Client type with the specified endpoint.
func NewClient(endpoint string, cred azcore.Credential, options *ClientOptions) (*Client, error) {
	if options == nil {
		o := DefaultClientOptions()
		options = &o
	}
	p := azcore.NewPipeline(options.HTTPClient,
		azcore.NewTelemetryPolicy(options.telemetryOptions()),
		azcore.NewUniqueRequestIDPolicy(),
		azcore.NewRetryPolicy(&options.Retry),
		cred.AuthenticationPolicy(azcore.AuthenticationPolicyOptions{Options: azcore.TokenRequestOptions{Scopes: []string{scope}}}),
		azcore.NewRequestLogPolicy(options.LogOptions))
	return NewClientWithPipeline(endpoint, p)
}

// NewClientWithPipeline creates an instance of the Client type with the specified endpoint and pipeline.
func NewClientWithPipeline(endpoint string, p azcore.Pipeline) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, azruntime.NewFrameError(err, azcore.Log().Should(azcore.LogStackTrace), 1, azcore.StackFrameCount)
	}
	if u.Scheme == "" {
		return nil, azruntime.NewFrameError(fmt.Errorf("no scheme detected in endpoint %s", endpoint), azcore.Log().Should(azcore.LogStackTrace), 1, azcore.StackFrameCount)
	}
	return &Client{u: u, p: p}, nil
}

// Operations returns the Operations associated with this client.
func (client *Client) Operations() Operations {
	return &operations{Client: client}
}

// AvailabilitySetsOperations returns the AvailabilitySetsOperations associated with this client.
func (client *Client) AvailabilitySetsOperations(subscriptionID string) AvailabilitySetsOperations {
	return &availabilitySetsOperations{Client: client, subscriptionID: subscriptionID}
}

// ProximityPlacementGroupsOperations returns the ProximityPlacementGroupsOperations associated with this client.
func (client *Client) ProximityPlacementGroupsOperations(subscriptionID string) ProximityPlacementGroupsOperations {
	return &proximityPlacementGroupsOperations{Client: client, subscriptionID: subscriptionID}
}

// DedicatedHostGroupsOperations returns the DedicatedHostGroupsOperations associated with this client.
func (client *Client) DedicatedHostGroupsOperations(subscriptionID string) DedicatedHostGroupsOperations {
	return &dedicatedHostGroupsOperations{Client: client, subscriptionID: subscriptionID}
}

// DedicatedHostsOperations returns the DedicatedHostsOperations associated with this client.
func (client *Client) DedicatedHostsOperations(subscriptionID string) DedicatedHostsOperations {
	return &dedicatedHostsOperations{Client: client, subscriptionID: subscriptionID}
}

// SSHPublicKeysOperations returns the SSHPublicKeysOperations associated with this client.
func (client *Client) SSHPublicKeysOperations(subscriptionID string) SSHPublicKeysOperations {
	return &sshPublicKeysOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineExtensionImagesOperations returns the VirtualMachineExtensionImagesOperations associated with this client.
func (client *Client) VirtualMachineExtensionImagesOperations(subscriptionID string) VirtualMachineExtensionImagesOperations {
	return &virtualMachineExtensionImagesOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineExtensionsOperations returns the VirtualMachineExtensionsOperations associated with this client.
func (client *Client) VirtualMachineExtensionsOperations(subscriptionID string) VirtualMachineExtensionsOperations {
	return &virtualMachineExtensionsOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineImagesOperations returns the VirtualMachineImagesOperations associated with this client.
func (client *Client) VirtualMachineImagesOperations(subscriptionID string) VirtualMachineImagesOperations {
	return &virtualMachineImagesOperations{Client: client, subscriptionID: subscriptionID}
}

// UsageOperations returns the UsageOperations associated with this client.
func (client *Client) UsageOperations(subscriptionID string) UsageOperations {
	return &usageOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachinesOperations returns the VirtualMachinesOperations associated with this client.
func (client *Client) VirtualMachinesOperations(subscriptionID string) VirtualMachinesOperations {
	return &virtualMachinesOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineSizesOperations returns the VirtualMachineSizesOperations associated with this client.
func (client *Client) VirtualMachineSizesOperations(subscriptionID string) VirtualMachineSizesOperations {
	return &virtualMachineSizesOperations{Client: client, subscriptionID: subscriptionID}
}

// ImagesOperations returns the ImagesOperations associated with this client.
func (client *Client) ImagesOperations(subscriptionID string) ImagesOperations {
	return &imagesOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineScaleSetsOperations returns the VirtualMachineScaleSetsOperations associated with this client.
func (client *Client) VirtualMachineScaleSetsOperations(subscriptionID string) VirtualMachineScaleSetsOperations {
	return &virtualMachineScaleSetsOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineScaleSetExtensionsOperations returns the VirtualMachineScaleSetExtensionsOperations associated with this client.
func (client *Client) VirtualMachineScaleSetExtensionsOperations(subscriptionID string) VirtualMachineScaleSetExtensionsOperations {
	return &virtualMachineScaleSetExtensionsOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineScaleSetRollingUpgradesOperations returns the VirtualMachineScaleSetRollingUpgradesOperations associated with this client.
func (client *Client) VirtualMachineScaleSetRollingUpgradesOperations(subscriptionID string) VirtualMachineScaleSetRollingUpgradesOperations {
	return &virtualMachineScaleSetRollingUpgradesOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineScaleSetVMExtensionsOperations returns the VirtualMachineScaleSetVMExtensionsOperations associated with this client.
func (client *Client) VirtualMachineScaleSetVMExtensionsOperations(subscriptionID string) VirtualMachineScaleSetVMExtensionsOperations {
	return &virtualMachineScaleSetVMExtensionsOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineScaleSetVMSOperations returns the VirtualMachineScaleSetVMSOperations associated with this client.
func (client *Client) VirtualMachineScaleSetVMSOperations(subscriptionID string) VirtualMachineScaleSetVMSOperations {
	return &virtualMachineScaleSetVmsOperations{Client: client, subscriptionID: subscriptionID}
}

// LogAnalyticsOperations returns the LogAnalyticsOperations associated with this client.
func (client *Client) LogAnalyticsOperations(subscriptionID string) LogAnalyticsOperations {
	return &logAnalyticsOperations{Client: client, subscriptionID: subscriptionID}
}

// VirtualMachineRunCommandsOperations returns the VirtualMachineRunCommandsOperations associated with this client.
func (client *Client) VirtualMachineRunCommandsOperations(subscriptionID string) VirtualMachineRunCommandsOperations {
	return &virtualMachineRunCommandsOperations{Client: client, subscriptionID: subscriptionID}
}

// ResourceSkusOperations returns the ResourceSkusOperations associated with this client.
func (client *Client) ResourceSkusOperations(subscriptionID string) ResourceSkusOperations {
	return &resourceSkusOperations{Client: client, subscriptionID: subscriptionID}
}

// DisksOperations returns the DisksOperations associated with this client.
func (client *Client) DisksOperations(subscriptionID string) DisksOperations {
	return &disksOperations{Client: client, subscriptionID: subscriptionID}
}

// SnapshotsOperations returns the SnapshotsOperations associated with this client.
func (client *Client) SnapshotsOperations(subscriptionID string) SnapshotsOperations {
	return &snapshotsOperations{Client: client, subscriptionID: subscriptionID}
}

// DiskEncryptionSetsOperations returns the DiskEncryptionSetsOperations associated with this client.
func (client *Client) DiskEncryptionSetsOperations(subscriptionID string) DiskEncryptionSetsOperations {
	return &diskEncryptionSetsOperations{Client: client, subscriptionID: subscriptionID}
}

// GalleriesOperations returns the GalleriesOperations associated with this client.
func (client *Client) GalleriesOperations(subscriptionID string) GalleriesOperations {
	return &galleriesOperations{Client: client, subscriptionID: subscriptionID}
}

// GalleryImagesOperations returns the GalleryImagesOperations associated with this client.
func (client *Client) GalleryImagesOperations(subscriptionID string) GalleryImagesOperations {
	return &galleryImagesOperations{Client: client, subscriptionID: subscriptionID}
}

// GalleryImageVersionsOperations returns the GalleryImageVersionsOperations associated with this client.
func (client *Client) GalleryImageVersionsOperations(subscriptionID string) GalleryImageVersionsOperations {
	return &galleryImageVersionsOperations{Client: client, subscriptionID: subscriptionID}
}

// GalleryApplicationsOperations returns the GalleryApplicationsOperations associated with this client.
func (client *Client) GalleryApplicationsOperations(subscriptionID string) GalleryApplicationsOperations {
	return &galleryApplicationsOperations{Client: client, subscriptionID: subscriptionID}
}

// GalleryApplicationVersionsOperations returns the GalleryApplicationVersionsOperations associated with this client.
func (client *Client) GalleryApplicationVersionsOperations(subscriptionID string) GalleryApplicationVersionsOperations {
	return &galleryApplicationVersionsOperations{Client: client, subscriptionID: subscriptionID}
}

// ContainerServicesOperations returns the ContainerServicesOperations associated with this client.
func (client *Client) ContainerServicesOperations(subscriptionID string) ContainerServicesOperations {
	return &containerServicesOperations{Client: client, subscriptionID: subscriptionID}
}
