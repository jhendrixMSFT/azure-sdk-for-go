// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package fake

import (
	"context"
	"errors"
	"fmt"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake/server"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute/v2"
	"net/http"
	"net/url"
	"regexp"
)

// MachineRunCommandsServer is a fake server for instances of the armhybridcompute.MachineRunCommandsClient type.
type MachineRunCommandsServer struct {
	// BeginCreateOrUpdate is the fake for method MachineRunCommandsClient.BeginCreateOrUpdate
	// HTTP status codes to indicate success: http.StatusOK, http.StatusCreated
	BeginCreateOrUpdate func(ctx context.Context, resourceGroupName string, machineName string, runCommandName string, runCommandProperties armhybridcompute.MachineRunCommand, options *armhybridcompute.MachineRunCommandsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder)

	// BeginDelete is the fake for method MachineRunCommandsClient.BeginDelete
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted, http.StatusNoContent
	BeginDelete func(ctx context.Context, resourceGroupName string, machineName string, runCommandName string, options *armhybridcompute.MachineRunCommandsClientBeginDeleteOptions) (resp azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientDeleteResponse], errResp azfake.ErrorResponder)

	// Get is the fake for method MachineRunCommandsClient.Get
	// HTTP status codes to indicate success: http.StatusOK
	Get func(ctx context.Context, resourceGroupName string, machineName string, runCommandName string, options *armhybridcompute.MachineRunCommandsClientGetOptions) (resp azfake.Responder[armhybridcompute.MachineRunCommandsClientGetResponse], errResp azfake.ErrorResponder)

	// NewListPager is the fake for method MachineRunCommandsClient.NewListPager
	// HTTP status codes to indicate success: http.StatusOK
	NewListPager func(resourceGroupName string, machineName string, options *armhybridcompute.MachineRunCommandsClientListOptions) (resp azfake.PagerResponder[armhybridcompute.MachineRunCommandsClientListResponse])
}

// NewMachineRunCommandsServerTransport creates a new instance of MachineRunCommandsServerTransport with the provided implementation.
// The returned MachineRunCommandsServerTransport instance is connected to an instance of armhybridcompute.MachineRunCommandsClient via the
// azcore.ClientOptions.Transporter field in the client's constructor parameters.
func NewMachineRunCommandsServerTransport(srv *MachineRunCommandsServer) *MachineRunCommandsServerTransport {
	return &MachineRunCommandsServerTransport{
		srv:                 srv,
		beginCreateOrUpdate: newTracker[azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientCreateOrUpdateResponse]](),
		beginDelete:         newTracker[azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientDeleteResponse]](),
		newListPager:        newTracker[azfake.PagerResponder[armhybridcompute.MachineRunCommandsClientListResponse]](),
	}
}

// MachineRunCommandsServerTransport connects instances of armhybridcompute.MachineRunCommandsClient to instances of MachineRunCommandsServer.
// Don't use this type directly, use NewMachineRunCommandsServerTransport instead.
type MachineRunCommandsServerTransport struct {
	srv                 *MachineRunCommandsServer
	beginCreateOrUpdate *tracker[azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientCreateOrUpdateResponse]]
	beginDelete         *tracker[azfake.PollerResponder[armhybridcompute.MachineRunCommandsClientDeleteResponse]]
	newListPager        *tracker[azfake.PagerResponder[armhybridcompute.MachineRunCommandsClientListResponse]]
}

// Do implements the policy.Transporter interface for MachineRunCommandsServerTransport.
func (m *MachineRunCommandsServerTransport) Do(req *http.Request) (*http.Response, error) {
	rawMethod := req.Context().Value(runtime.CtxAPINameKey{})
	method, ok := rawMethod.(string)
	if !ok {
		return nil, nonRetriableError{errors.New("unable to dispatch request, missing value for CtxAPINameKey")}
	}

	return m.dispatchToMethodFake(req, method)
}

func (m *MachineRunCommandsServerTransport) dispatchToMethodFake(req *http.Request, method string) (*http.Response, error) {
	resultChan := make(chan result)
	defer close(resultChan)

	go func() {
		var intercepted bool
		var res result
		if machineRunCommandsServerTransportInterceptor != nil {
			res.resp, res.err, intercepted = machineRunCommandsServerTransportInterceptor.Do(req)
		}
		if !intercepted {
			switch method {
			case "MachineRunCommandsClient.BeginCreateOrUpdate":
				res.resp, res.err = m.dispatchBeginCreateOrUpdate(req)
			case "MachineRunCommandsClient.BeginDelete":
				res.resp, res.err = m.dispatchBeginDelete(req)
			case "MachineRunCommandsClient.Get":
				res.resp, res.err = m.dispatchGet(req)
			case "MachineRunCommandsClient.NewListPager":
				res.resp, res.err = m.dispatchNewListPager(req)
			default:
				res.err = fmt.Errorf("unhandled API %s", method)
			}

		}
		select {
		case resultChan <- res:
		case <-req.Context().Done():
		}
	}()

	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case res := <-resultChan:
		return res.resp, res.err
	}
}

func (m *MachineRunCommandsServerTransport) dispatchBeginCreateOrUpdate(req *http.Request) (*http.Response, error) {
	if m.srv.BeginCreateOrUpdate == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginCreateOrUpdate not implemented")}
	}
	beginCreateOrUpdate := m.beginCreateOrUpdate.get(req)
	if beginCreateOrUpdate == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.HybridCompute/machines/(?P<machineName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/runCommands/(?P<runCommandName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 4 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		body, err := server.UnmarshalRequestAsJSON[armhybridcompute.MachineRunCommand](req)
		if err != nil {
			return nil, err
		}
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		machineNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("machineName")])
		if err != nil {
			return nil, err
		}
		runCommandNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("runCommandName")])
		if err != nil {
			return nil, err
		}
		respr, errRespr := m.srv.BeginCreateOrUpdate(req.Context(), resourceGroupNameParam, machineNameParam, runCommandNameParam, body, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginCreateOrUpdate = &respr
		m.beginCreateOrUpdate.add(req, beginCreateOrUpdate)
	}

	resp, err := server.PollerResponderNext(beginCreateOrUpdate, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusCreated}, resp.StatusCode) {
		m.beginCreateOrUpdate.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusCreated", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginCreateOrUpdate) {
		m.beginCreateOrUpdate.remove(req)
	}

	return resp, nil
}

func (m *MachineRunCommandsServerTransport) dispatchBeginDelete(req *http.Request) (*http.Response, error) {
	if m.srv.BeginDelete == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginDelete not implemented")}
	}
	beginDelete := m.beginDelete.get(req)
	if beginDelete == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.HybridCompute/machines/(?P<machineName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/runCommands/(?P<runCommandName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 4 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		machineNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("machineName")])
		if err != nil {
			return nil, err
		}
		runCommandNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("runCommandName")])
		if err != nil {
			return nil, err
		}
		respr, errRespr := m.srv.BeginDelete(req.Context(), resourceGroupNameParam, machineNameParam, runCommandNameParam, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginDelete = &respr
		m.beginDelete.add(req, beginDelete)
	}

	resp, err := server.PollerResponderNext(beginDelete, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted, http.StatusNoContent}, resp.StatusCode) {
		m.beginDelete.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted, http.StatusNoContent", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginDelete) {
		m.beginDelete.remove(req)
	}

	return resp, nil
}

func (m *MachineRunCommandsServerTransport) dispatchGet(req *http.Request) (*http.Response, error) {
	if m.srv.Get == nil {
		return nil, &nonRetriableError{errors.New("fake for method Get not implemented")}
	}
	const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.HybridCompute/machines/(?P<machineName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/runCommands/(?P<runCommandName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)`
	regex := regexp.MustCompile(regexStr)
	matches := regex.FindStringSubmatch(req.URL.EscapedPath())
	if matches == nil || len(matches) < 4 {
		return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
	}
	resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
	if err != nil {
		return nil, err
	}
	machineNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("machineName")])
	if err != nil {
		return nil, err
	}
	runCommandNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("runCommandName")])
	if err != nil {
		return nil, err
	}
	respr, errRespr := m.srv.Get(req.Context(), resourceGroupNameParam, machineNameParam, runCommandNameParam, nil)
	if respErr := server.GetError(errRespr, req); respErr != nil {
		return nil, respErr
	}
	respContent := server.GetResponseContent(respr)
	if !contains([]int{http.StatusOK}, respContent.HTTPStatus) {
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", respContent.HTTPStatus)}
	}
	resp, err := server.MarshalResponseAsJSON(respContent, server.GetResponse(respr).MachineRunCommand, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (m *MachineRunCommandsServerTransport) dispatchNewListPager(req *http.Request) (*http.Response, error) {
	if m.srv.NewListPager == nil {
		return nil, &nonRetriableError{errors.New("fake for method NewListPager not implemented")}
	}
	newListPager := m.newListPager.get(req)
	if newListPager == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/resourceGroups/(?P<resourceGroupName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Microsoft\.HybridCompute/machines/(?P<machineName>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/runCommands`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if matches == nil || len(matches) < 3 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		qp := req.URL.Query()
		resourceGroupNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("resourceGroupName")])
		if err != nil {
			return nil, err
		}
		machineNameParam, err := url.PathUnescape(matches[regex.SubexpIndex("machineName")])
		if err != nil {
			return nil, err
		}
		expandUnescaped, err := url.QueryUnescape(qp.Get("$expand"))
		if err != nil {
			return nil, err
		}
		expandParam := getOptional(expandUnescaped)
		var options *armhybridcompute.MachineRunCommandsClientListOptions
		if expandParam != nil {
			options = &armhybridcompute.MachineRunCommandsClientListOptions{
				Expand: expandParam,
			}
		}
		resp := m.srv.NewListPager(resourceGroupNameParam, machineNameParam, options)
		newListPager = &resp
		m.newListPager.add(req, newListPager)
		server.PagerResponderInjectNextLinks(newListPager, req, func(page *armhybridcompute.MachineRunCommandsClientListResponse, createLink func() string) {
			page.NextLink = to.Ptr(createLink())
		})
	}
	resp, err := server.PagerResponderNext(newListPager, req)
	if err != nil {
		return nil, err
	}
	if !contains([]int{http.StatusOK}, resp.StatusCode) {
		m.newListPager.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", resp.StatusCode)}
	}
	if !server.PagerResponderMore(newListPager) {
		m.newListPager.remove(req)
	}
	return resp, nil
}

// set this to conditionally intercept incoming requests to MachineRunCommandsServerTransport
var machineRunCommandsServerTransportInterceptor interface {
	// Do returns true if the server transport should use the returned response/error
	Do(*http.Request) (*http.Response, error, bool)
}
