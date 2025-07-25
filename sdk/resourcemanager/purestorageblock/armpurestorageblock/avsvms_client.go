// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) Go Code Generator. DO NOT EDIT.

package armpurestorageblock

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// AvsVMsClient contains the methods for the AvsVMs group.
// Don't use this type directly, use NewAvsVMsClient() instead.
type AvsVMsClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewAvsVMsClient creates a new instance of AvsVMsClient with the specified values.
//   - subscriptionID - The ID of the target subscription. The value must be an UUID.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewAvsVMsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*AvsVMsClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &AvsVMsClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// BeginDelete - Delete an AVS VM
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-11-01
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - storagePoolName - Name of the storage pool
//   - avsVMID - ID of the AVS VM
//   - options - AvsVMsClientBeginDeleteOptions contains the optional parameters for the AvsVMsClient.BeginDelete method.
func (client *AvsVMsClient) BeginDelete(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, options *AvsVMsClientBeginDeleteOptions) (*runtime.Poller[AvsVMsClientDeleteResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.deleteOperation(ctx, resourceGroupName, storagePoolName, avsVMID, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[AvsVMsClientDeleteResponse]{
			Tracer: client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[AvsVMsClientDeleteResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Delete - Delete an AVS VM
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-11-01
func (client *AvsVMsClient) deleteOperation(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, options *AvsVMsClientBeginDeleteOptions) (*http.Response, error) {
	var err error
	const operationName = "AvsVMsClient.BeginDelete"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, storagePoolName, avsVMID, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusAccepted, http.StatusNoContent) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *AvsVMsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, _ *AvsVMsClientBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/PureStorage.Block/storagePools/{storagePoolName}/avsVms/{avsVmId}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if storagePoolName == "" {
		return nil, errors.New("parameter storagePoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{storagePoolName}", url.PathEscape(storagePoolName))
	if avsVMID == "" {
		return nil, errors.New("parameter avsVMID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{avsVmId}", url.PathEscape(avsVMID))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// Get - Get an AVS VM
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-11-01
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - storagePoolName - Name of the storage pool
//   - avsVMID - ID of the AVS VM
//   - options - AvsVMsClientGetOptions contains the optional parameters for the AvsVMsClient.Get method.
func (client *AvsVMsClient) Get(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, options *AvsVMsClientGetOptions) (AvsVMsClientGetResponse, error) {
	var err error
	const operationName = "AvsVMsClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, storagePoolName, avsVMID, options)
	if err != nil {
		return AvsVMsClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return AvsVMsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return AvsVMsClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *AvsVMsClient) getCreateRequest(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, _ *AvsVMsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/PureStorage.Block/storagePools/{storagePoolName}/avsVms/{avsVmId}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if storagePoolName == "" {
		return nil, errors.New("parameter storagePoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{storagePoolName}", url.PathEscape(storagePoolName))
	if avsVMID == "" {
		return nil, errors.New("parameter avsVMID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{avsVmId}", url.PathEscape(avsVMID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *AvsVMsClient) getHandleResponse(resp *http.Response) (AvsVMsClientGetResponse, error) {
	result := AvsVMsClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.AvsVM); err != nil {
		return AvsVMsClientGetResponse{}, err
	}
	return result, nil
}

// NewListByStoragePoolPager - List AVS VMs by storage pool
//
// Generated from API version 2024-11-01
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - storagePoolName - Name of the storage pool
//   - options - AvsVMsClientListByStoragePoolOptions contains the optional parameters for the AvsVMsClient.NewListByStoragePoolPager
//     method.
func (client *AvsVMsClient) NewListByStoragePoolPager(resourceGroupName string, storagePoolName string, options *AvsVMsClientListByStoragePoolOptions) *runtime.Pager[AvsVMsClientListByStoragePoolResponse] {
	return runtime.NewPager(runtime.PagingHandler[AvsVMsClientListByStoragePoolResponse]{
		More: func(page AvsVMsClientListByStoragePoolResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *AvsVMsClientListByStoragePoolResponse) (AvsVMsClientListByStoragePoolResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "AvsVMsClient.NewListByStoragePoolPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listByStoragePoolCreateRequest(ctx, resourceGroupName, storagePoolName, options)
			}, nil)
			if err != nil {
				return AvsVMsClientListByStoragePoolResponse{}, err
			}
			return client.listByStoragePoolHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listByStoragePoolCreateRequest creates the ListByStoragePool request.
func (client *AvsVMsClient) listByStoragePoolCreateRequest(ctx context.Context, resourceGroupName string, storagePoolName string, _ *AvsVMsClientListByStoragePoolOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/PureStorage.Block/storagePools/{storagePoolName}/avsVms"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if storagePoolName == "" {
		return nil, errors.New("parameter storagePoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{storagePoolName}", url.PathEscape(storagePoolName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listByStoragePoolHandleResponse handles the ListByStoragePool response.
func (client *AvsVMsClient) listByStoragePoolHandleResponse(resp *http.Response) (AvsVMsClientListByStoragePoolResponse, error) {
	result := AvsVMsClientListByStoragePoolResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.AvsVMListResult); err != nil {
		return AvsVMsClientListByStoragePoolResponse{}, err
	}
	return result, nil
}

// BeginUpdate - Update an AVS VM
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-11-01
//   - resourceGroupName - The name of the resource group. The name is case insensitive.
//   - storagePoolName - Name of the storage pool
//   - avsVMID - ID of the AVS VM
//   - properties - The resource properties to be updated.
//   - options - AvsVMsClientBeginUpdateOptions contains the optional parameters for the AvsVMsClient.BeginUpdate method.
func (client *AvsVMsClient) BeginUpdate(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, properties AvsVMUpdate, options *AvsVMsClientBeginUpdateOptions) (*runtime.Poller[AvsVMsClientUpdateResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.update(ctx, resourceGroupName, storagePoolName, avsVMID, properties, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[AvsVMsClientUpdateResponse]{
			Tracer: client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[AvsVMsClientUpdateResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Update - Update an AVS VM
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-11-01
func (client *AvsVMsClient) update(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, properties AvsVMUpdate, options *AvsVMsClientBeginUpdateOptions) (*http.Response, error) {
	var err error
	const operationName = "AvsVMsClient.BeginUpdate"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.updateCreateRequest(ctx, resourceGroupName, storagePoolName, avsVMID, properties, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusAccepted) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// updateCreateRequest creates the Update request.
func (client *AvsVMsClient) updateCreateRequest(ctx context.Context, resourceGroupName string, storagePoolName string, avsVMID string, properties AvsVMUpdate, _ *AvsVMsClientBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/PureStorage.Block/storagePools/{storagePoolName}/avsVms/{avsVmId}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if storagePoolName == "" {
		return nil, errors.New("parameter storagePoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{storagePoolName}", url.PathEscape(storagePoolName))
	if avsVMID == "" {
		return nil, errors.New("parameter avsVMID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{avsVmId}", url.PathEscape(avsVMID))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	req.Raw().Header["Content-Type"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, properties); err != nil {
		return nil, err
	}
	return req, nil
}
