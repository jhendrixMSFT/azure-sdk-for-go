// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmonitor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
)

// EventCategoriesOperations contains the methods for the EventCategories group.
type EventCategoriesOperations interface {
	// List - Get the list of available event categories supported in the Activity Logs Service.<br>The current list includes the following: Administrative, Security, ServiceHealth, Alert, Recommendation, Policy.
	List(ctx context.Context) (*EventCategoryCollectionResponse, error)
}

// eventCategoriesOperations implements the EventCategoriesOperations interface.
type eventCategoriesOperations struct {
	*Client
}

// List - Get the list of available event categories supported in the Activity Logs Service.<br>The current list includes the following: Administrative, Security, ServiceHealth, Alert, Recommendation, Policy.
func (client *eventCategoriesOperations) List(ctx context.Context) (*EventCategoryCollectionResponse, error) {
	req, err := client.listCreateRequest()
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.listHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// listCreateRequest creates the List request.
func (client *eventCategoriesOperations) listCreateRequest() (*azcore.Request, error) {
	urlPath := "/providers/microsoft.insights/eventcategories"
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2015-04-01")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodGet, *u)
	return req, nil
}

// listHandleResponse handles the List response.
func (client *eventCategoriesOperations) listHandleResponse(resp *azcore.Response) (*EventCategoryCollectionResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.listHandleError(resp)
	}
	result := EventCategoryCollectionResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.EventCategoryCollection)
}

// listHandleError handles the List error response.
func (client *eventCategoriesOperations) listHandleError(resp *azcore.Response) error {
	var err ErrorResponse
	if err := resp.UnmarshalAsJSON(&err); err != nil {
		return err
	}
	return err
}