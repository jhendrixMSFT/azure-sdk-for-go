//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
// DO NOT EDIT.

package armresources_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
)

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/CreateResourceGroup.json
func ExampleResourceGroupsClient_CreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	res, err := clientFactory.NewResourceGroupsClient().CreateOrUpdate(ctx, "my-resource-group", armresources.ResourceGroup{
		Location: to.Ptr("eastus"),
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.ResourceGroup = armresources.ResourceGroup{
	// 	Name: to.Ptr("my-resource-group"),
	// 	ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-resource-group"),
	// 	Location: to.Ptr("eastus"),
	// 	Properties: &armresources.ResourceGroupProperties{
	// 		ProvisioningState: to.Ptr("Succeeded"),
	// 	},
	// }
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/ForceDeleteVMsAndVMSSInResourceGroup.json
func ExampleResourceGroupsClient_BeginDelete_forceDeleteAllTheVirtualMachinesAndVirtualMachineScaleSetsInAResourceGroup() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewResourceGroupsClient().BeginDelete(ctx, "my-resource-group", &armresources.ResourceGroupsClientBeginDeleteOptions{ForceDeletionTypes: to.Ptr("Microsoft.Compute/virtualMachines,Microsoft.Compute/virtualMachineScaleSets")})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/ForceDeleteVMsInResourceGroup.json
func ExampleResourceGroupsClient_BeginDelete_forceDeleteAllTheVirtualMachinesInAResourceGroup() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewResourceGroupsClient().BeginDelete(ctx, "my-resource-group", &armresources.ResourceGroupsClientBeginDeleteOptions{ForceDeletionTypes: to.Ptr("Microsoft.Compute/virtualMachines")})
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/ExportResourceGroup.json
func ExampleResourceGroupsClient_BeginExportTemplate_exportAResourceGroup() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewResourceGroupsClient().BeginExportTemplate(ctx, "my-resource-group", armresources.ExportTemplateRequest{
		Options: to.Ptr("IncludeParameterDefaultValue,IncludeComments"),
		Resources: []*string{
			to.Ptr("*")},
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.ResourceGroupExportResult = armresources.ResourceGroupExportResult{
	// 	Error: &armresources.ErrorResponse{
	// 		Code: to.Ptr("ExportTemplateCompletedWithErrors"),
	// 		Message: to.Ptr("Export template operation completed with errors. Some resources were not exported. Please see details for more information."),
	// 		Details: []*armresources.ErrorResponse{
	// 		},
	// 	},
	// 	Template: map[string]any{
	// 		"$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
	// 		"contentVersion": "1.0.0.0",
	// 		"parameters":map[string]any{
	// 			"myResourceType_myFirstResource_name":map[string]any{
	// 				"type": "String",
	// 				"defaultValue": "myFirstResource",
	// 			},
	// 			"myResourceType_myFirstResource_secret":map[string]any{
	// 				"type": "SecureString",
	// 				"defaultValue": nil,
	// 			},
	// 			"myResourceType_mySecondResource_name":map[string]any{
	// 				"type": "String",
	// 				"defaultValue": "mySecondResource",
	// 			},
	// 		},
	// 		"resources":[]any{
	// 			map[string]any{
	// 				"name": "[parameters('myResourceType_myFirstResource_name')]",
	// 				"type": "My.RP/myResourceType",
	// 				"apiVersion": "2019-01-01",
	// 				"location": "West US",
	// 				"properties":map[string]any{
	// 					"secret": "[parameters('myResourceType_myFirstResource_secret')]",
	// 				},
	// 			},
	// 			map[string]any{
	// 				"name": "[parameters('myResourceType_mySecondResource_name')]",
	// 				"type": "My.RP/myResourceType",
	// 				"apiVersion": "2019-01-01",
	// 				"location": "West US",
	// 				"properties":map[string]any{
	// 					"customProperty": "hello!",
	// 				},
	// 			},
	// 		},
	// 		"variables":map[string]any{
	// 		},
	// 	},
	// }
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/ExportResourceGroupAsBicep.json
func ExampleResourceGroupsClient_BeginExportTemplate_exportAResourceGroupAsBicep() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewResourceGroupsClient().BeginExportTemplate(ctx, "my-resource-group", armresources.ExportTemplateRequest{
		Options:      to.Ptr("IncludeParameterDefaultValue,IncludeComments"),
		OutputFormat: to.Ptr(armresources.ExportTemplateOutputFormatBicep),
		Resources: []*string{
			to.Ptr("*")},
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.ResourceGroupExportResult = armresources.ResourceGroupExportResult{
	// 	Error: &armresources.ErrorResponse{
	// 		Code: to.Ptr("ExportTemplateCompletedWithErrors"),
	// 		Message: to.Ptr("Export template operation completed with errors. Some resources were not exported. Please see details for more information."),
	// 		Details: []*armresources.ErrorResponse{
	// 		},
	// 	},
	// 	Output: to.Ptr("\nparam myResourceType_myFirstResource_name string = 'myFirstResource'\nparam myResourceType_mySecondResource_name string = 'mySecondResource'\n\n@secure()\nparam myResourceType_myFirstResource_secret string = null\n\nresource myResourceType_myFirstResource_name_resource 'My.RP/myResourceType@2019-01-01' = {\n  name: myResourceType_myFirstResource_name\n  location: 'West US'\n  properties: {\n    secret: myResourceType_myFirstResource_secret\n  }\n}\n\nresource myResourceType_mySecondResource_name_resource 'My.RP/myResourceType@2019-01-01' = {\n  name: myResourceType_mySecondResource_name\n  location: 'West US'\n  properties: {\n    customProperty: 'hello!'\n  }\n}\n"),
	// }
}

// Generated from example definition: https://github.com/Azure/azure-rest-api-specs/blob/4a2bb0762eaad11e725516708483598e0c12cabb/specification/resources/resource-manager/Microsoft.Resources/stable/2025-04-01/examples/ExportResourceGroupWithFiltering.json
func ExampleResourceGroupsClient_BeginExportTemplate_exportAResourceGroupWithFiltering() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armresources.NewClientFactory("<subscription-id>", cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	poller, err := clientFactory.NewResourceGroupsClient().BeginExportTemplate(ctx, "my-resource-group", armresources.ExportTemplateRequest{
		Options: to.Ptr("SkipResourceNameParameterization"),
		Resources: []*string{
			to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-resource-group/providers/My.RP/myResourceType/myFirstResource")},
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
	// You could use response here. We use blank identifier for just demo purposes.
	_ = res
	// If the HTTP response code is 200 as defined in example definition, your response structure would look as follows. Please pay attention that all the values in the output are fake values for just demo purposes.
	// res.ResourceGroupExportResult = armresources.ResourceGroupExportResult{
	// 	Template: map[string]any{
	// 		"$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
	// 		"contentVersion": "1.0.0.0",
	// 		"parameters":map[string]any{
	// 			"myResourceType_myFirstResource_secret":map[string]any{
	// 				"type": "SecureString",
	// 				"defaultValue": nil,
	// 			},
	// 		},
	// 		"resources":[]any{
	// 			map[string]any{
	// 				"name": "myFirstResource",
	// 				"type": "My.RP/myResourceType",
	// 				"apiVersion": "2019-01-01",
	// 				"location": "West US",
	// 				"properties":map[string]any{
	// 					"secret": "[parameters('myResourceType_myFirstResource_secret')]",
	// 				},
	// 			},
	// 		},
	// 		"variables":map[string]any{
	// 		},
	// 	},
	// }
}
