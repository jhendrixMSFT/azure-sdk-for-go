// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) Go Code Generator. DO NOT EDIT.

package fake

import (
	"context"
	"errors"
	"fmt"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake/server"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/oracledatabase/armoracledatabase"
	"net/http"
	"regexp"
)

// OracleSubscriptionsServer is a fake server for instances of the armoracledatabase.OracleSubscriptionsClient type.
type OracleSubscriptionsServer struct {
	// BeginAddAzureSubscriptions is the fake for method OracleSubscriptionsClient.BeginAddAzureSubscriptions
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted, http.StatusNoContent
	BeginAddAzureSubscriptions func(ctx context.Context, body armoracledatabase.AzureSubscriptions, options *armoracledatabase.OracleSubscriptionsClientBeginAddAzureSubscriptionsOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientAddAzureSubscriptionsResponse], errResp azfake.ErrorResponder)

	// BeginCreateOrUpdate is the fake for method OracleSubscriptionsClient.BeginCreateOrUpdate
	// HTTP status codes to indicate success: http.StatusOK, http.StatusCreated
	BeginCreateOrUpdate func(ctx context.Context, resource armoracledatabase.OracleSubscription, options *armoracledatabase.OracleSubscriptionsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder)

	// BeginDelete is the fake for method OracleSubscriptionsClient.BeginDelete
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted, http.StatusNoContent
	BeginDelete func(ctx context.Context, options *armoracledatabase.OracleSubscriptionsClientBeginDeleteOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientDeleteResponse], errResp azfake.ErrorResponder)

	// Get is the fake for method OracleSubscriptionsClient.Get
	// HTTP status codes to indicate success: http.StatusOK
	Get func(ctx context.Context, options *armoracledatabase.OracleSubscriptionsClientGetOptions) (resp azfake.Responder[armoracledatabase.OracleSubscriptionsClientGetResponse], errResp azfake.ErrorResponder)

	// BeginListActivationLinks is the fake for method OracleSubscriptionsClient.BeginListActivationLinks
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted
	BeginListActivationLinks func(ctx context.Context, options *armoracledatabase.OracleSubscriptionsClientBeginListActivationLinksOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListActivationLinksResponse], errResp azfake.ErrorResponder)

	// NewListBySubscriptionPager is the fake for method OracleSubscriptionsClient.NewListBySubscriptionPager
	// HTTP status codes to indicate success: http.StatusOK
	NewListBySubscriptionPager func(options *armoracledatabase.OracleSubscriptionsClientListBySubscriptionOptions) (resp azfake.PagerResponder[armoracledatabase.OracleSubscriptionsClientListBySubscriptionResponse])

	// BeginListCloudAccountDetails is the fake for method OracleSubscriptionsClient.BeginListCloudAccountDetails
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted
	BeginListCloudAccountDetails func(ctx context.Context, options *armoracledatabase.OracleSubscriptionsClientBeginListCloudAccountDetailsOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListCloudAccountDetailsResponse], errResp azfake.ErrorResponder)

	// BeginListSaasSubscriptionDetails is the fake for method OracleSubscriptionsClient.BeginListSaasSubscriptionDetails
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted
	BeginListSaasSubscriptionDetails func(ctx context.Context, options *armoracledatabase.OracleSubscriptionsClientBeginListSaasSubscriptionDetailsOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListSaasSubscriptionDetailsResponse], errResp azfake.ErrorResponder)

	// BeginUpdate is the fake for method OracleSubscriptionsClient.BeginUpdate
	// HTTP status codes to indicate success: http.StatusOK, http.StatusAccepted
	BeginUpdate func(ctx context.Context, properties armoracledatabase.OracleSubscriptionUpdate, options *armoracledatabase.OracleSubscriptionsClientBeginUpdateOptions) (resp azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientUpdateResponse], errResp azfake.ErrorResponder)
}

// NewOracleSubscriptionsServerTransport creates a new instance of OracleSubscriptionsServerTransport with the provided implementation.
// The returned OracleSubscriptionsServerTransport instance is connected to an instance of armoracledatabase.OracleSubscriptionsClient via the
// azcore.ClientOptions.Transporter field in the client's constructor parameters.
func NewOracleSubscriptionsServerTransport(srv *OracleSubscriptionsServer) *OracleSubscriptionsServerTransport {
	return &OracleSubscriptionsServerTransport{
		srv:                              srv,
		beginAddAzureSubscriptions:       newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientAddAzureSubscriptionsResponse]](),
		beginCreateOrUpdate:              newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientCreateOrUpdateResponse]](),
		beginDelete:                      newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientDeleteResponse]](),
		beginListActivationLinks:         newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListActivationLinksResponse]](),
		newListBySubscriptionPager:       newTracker[azfake.PagerResponder[armoracledatabase.OracleSubscriptionsClientListBySubscriptionResponse]](),
		beginListCloudAccountDetails:     newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListCloudAccountDetailsResponse]](),
		beginListSaasSubscriptionDetails: newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListSaasSubscriptionDetailsResponse]](),
		beginUpdate:                      newTracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientUpdateResponse]](),
	}
}

// OracleSubscriptionsServerTransport connects instances of armoracledatabase.OracleSubscriptionsClient to instances of OracleSubscriptionsServer.
// Don't use this type directly, use NewOracleSubscriptionsServerTransport instead.
type OracleSubscriptionsServerTransport struct {
	srv                              *OracleSubscriptionsServer
	beginAddAzureSubscriptions       *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientAddAzureSubscriptionsResponse]]
	beginCreateOrUpdate              *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientCreateOrUpdateResponse]]
	beginDelete                      *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientDeleteResponse]]
	beginListActivationLinks         *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListActivationLinksResponse]]
	newListBySubscriptionPager       *tracker[azfake.PagerResponder[armoracledatabase.OracleSubscriptionsClientListBySubscriptionResponse]]
	beginListCloudAccountDetails     *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListCloudAccountDetailsResponse]]
	beginListSaasSubscriptionDetails *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientListSaasSubscriptionDetailsResponse]]
	beginUpdate                      *tracker[azfake.PollerResponder[armoracledatabase.OracleSubscriptionsClientUpdateResponse]]
}

// Do implements the policy.Transporter interface for OracleSubscriptionsServerTransport.
func (o *OracleSubscriptionsServerTransport) Do(req *http.Request) (*http.Response, error) {
	rawMethod := req.Context().Value(runtime.CtxAPINameKey{})
	method, ok := rawMethod.(string)
	if !ok {
		return nil, nonRetriableError{errors.New("unable to dispatch request, missing value for CtxAPINameKey")}
	}

	return o.dispatchToMethodFake(req, method)
}

func (o *OracleSubscriptionsServerTransport) dispatchToMethodFake(req *http.Request, method string) (*http.Response, error) {
	resultChan := make(chan result)
	defer close(resultChan)

	go func() {
		var intercepted bool
		var res result
		if oracleSubscriptionsServerTransportInterceptor != nil {
			res.resp, res.err, intercepted = oracleSubscriptionsServerTransportInterceptor.Do(req)
		}
		if !intercepted {
			switch method {
			case "OracleSubscriptionsClient.BeginAddAzureSubscriptions":
				res.resp, res.err = o.dispatchBeginAddAzureSubscriptions(req)
			case "OracleSubscriptionsClient.BeginCreateOrUpdate":
				res.resp, res.err = o.dispatchBeginCreateOrUpdate(req)
			case "OracleSubscriptionsClient.BeginDelete":
				res.resp, res.err = o.dispatchBeginDelete(req)
			case "OracleSubscriptionsClient.Get":
				res.resp, res.err = o.dispatchGet(req)
			case "OracleSubscriptionsClient.BeginListActivationLinks":
				res.resp, res.err = o.dispatchBeginListActivationLinks(req)
			case "OracleSubscriptionsClient.NewListBySubscriptionPager":
				res.resp, res.err = o.dispatchNewListBySubscriptionPager(req)
			case "OracleSubscriptionsClient.BeginListCloudAccountDetails":
				res.resp, res.err = o.dispatchBeginListCloudAccountDetails(req)
			case "OracleSubscriptionsClient.BeginListSaasSubscriptionDetails":
				res.resp, res.err = o.dispatchBeginListSaasSubscriptionDetails(req)
			case "OracleSubscriptionsClient.BeginUpdate":
				res.resp, res.err = o.dispatchBeginUpdate(req)
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

func (o *OracleSubscriptionsServerTransport) dispatchBeginAddAzureSubscriptions(req *http.Request) (*http.Response, error) {
	if o.srv.BeginAddAzureSubscriptions == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginAddAzureSubscriptions not implemented")}
	}
	beginAddAzureSubscriptions := o.beginAddAzureSubscriptions.get(req)
	if beginAddAzureSubscriptions == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default/addAzureSubscriptions`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		body, err := server.UnmarshalRequestAsJSON[armoracledatabase.AzureSubscriptions](req)
		if err != nil {
			return nil, err
		}
		respr, errRespr := o.srv.BeginAddAzureSubscriptions(req.Context(), body, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginAddAzureSubscriptions = &respr
		o.beginAddAzureSubscriptions.add(req, beginAddAzureSubscriptions)
	}

	resp, err := server.PollerResponderNext(beginAddAzureSubscriptions, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted, http.StatusNoContent}, resp.StatusCode) {
		o.beginAddAzureSubscriptions.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted, http.StatusNoContent", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginAddAzureSubscriptions) {
		o.beginAddAzureSubscriptions.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginCreateOrUpdate(req *http.Request) (*http.Response, error) {
	if o.srv.BeginCreateOrUpdate == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginCreateOrUpdate not implemented")}
	}
	beginCreateOrUpdate := o.beginCreateOrUpdate.get(req)
	if beginCreateOrUpdate == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		body, err := server.UnmarshalRequestAsJSON[armoracledatabase.OracleSubscription](req)
		if err != nil {
			return nil, err
		}
		respr, errRespr := o.srv.BeginCreateOrUpdate(req.Context(), body, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginCreateOrUpdate = &respr
		o.beginCreateOrUpdate.add(req, beginCreateOrUpdate)
	}

	resp, err := server.PollerResponderNext(beginCreateOrUpdate, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusCreated}, resp.StatusCode) {
		o.beginCreateOrUpdate.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusCreated", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginCreateOrUpdate) {
		o.beginCreateOrUpdate.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginDelete(req *http.Request) (*http.Response, error) {
	if o.srv.BeginDelete == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginDelete not implemented")}
	}
	beginDelete := o.beginDelete.get(req)
	if beginDelete == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		respr, errRespr := o.srv.BeginDelete(req.Context(), nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginDelete = &respr
		o.beginDelete.add(req, beginDelete)
	}

	resp, err := server.PollerResponderNext(beginDelete, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted, http.StatusNoContent}, resp.StatusCode) {
		o.beginDelete.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted, http.StatusNoContent", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginDelete) {
		o.beginDelete.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchGet(req *http.Request) (*http.Response, error) {
	if o.srv.Get == nil {
		return nil, &nonRetriableError{errors.New("fake for method Get not implemented")}
	}
	const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default`
	regex := regexp.MustCompile(regexStr)
	matches := regex.FindStringSubmatch(req.URL.EscapedPath())
	if len(matches) < 2 {
		return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
	}
	respr, errRespr := o.srv.Get(req.Context(), nil)
	if respErr := server.GetError(errRespr, req); respErr != nil {
		return nil, respErr
	}
	respContent := server.GetResponseContent(respr)
	if !contains([]int{http.StatusOK}, respContent.HTTPStatus) {
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", respContent.HTTPStatus)}
	}
	resp, err := server.MarshalResponseAsJSON(respContent, server.GetResponse(respr).OracleSubscription, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginListActivationLinks(req *http.Request) (*http.Response, error) {
	if o.srv.BeginListActivationLinks == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginListActivationLinks not implemented")}
	}
	beginListActivationLinks := o.beginListActivationLinks.get(req)
	if beginListActivationLinks == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default/listActivationLinks`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		respr, errRespr := o.srv.BeginListActivationLinks(req.Context(), nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginListActivationLinks = &respr
		o.beginListActivationLinks.add(req, beginListActivationLinks)
	}

	resp, err := server.PollerResponderNext(beginListActivationLinks, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted}, resp.StatusCode) {
		o.beginListActivationLinks.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginListActivationLinks) {
		o.beginListActivationLinks.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchNewListBySubscriptionPager(req *http.Request) (*http.Response, error) {
	if o.srv.NewListBySubscriptionPager == nil {
		return nil, &nonRetriableError{errors.New("fake for method NewListBySubscriptionPager not implemented")}
	}
	newListBySubscriptionPager := o.newListBySubscriptionPager.get(req)
	if newListBySubscriptionPager == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		resp := o.srv.NewListBySubscriptionPager(nil)
		newListBySubscriptionPager = &resp
		o.newListBySubscriptionPager.add(req, newListBySubscriptionPager)
		server.PagerResponderInjectNextLinks(newListBySubscriptionPager, req, func(page *armoracledatabase.OracleSubscriptionsClientListBySubscriptionResponse, createLink func() string) {
			page.NextLink = to.Ptr(createLink())
		})
	}
	resp, err := server.PagerResponderNext(newListBySubscriptionPager, req)
	if err != nil {
		return nil, err
	}
	if !contains([]int{http.StatusOK}, resp.StatusCode) {
		o.newListBySubscriptionPager.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK", resp.StatusCode)}
	}
	if !server.PagerResponderMore(newListBySubscriptionPager) {
		o.newListBySubscriptionPager.remove(req)
	}
	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginListCloudAccountDetails(req *http.Request) (*http.Response, error) {
	if o.srv.BeginListCloudAccountDetails == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginListCloudAccountDetails not implemented")}
	}
	beginListCloudAccountDetails := o.beginListCloudAccountDetails.get(req)
	if beginListCloudAccountDetails == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default/listCloudAccountDetails`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		respr, errRespr := o.srv.BeginListCloudAccountDetails(req.Context(), nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginListCloudAccountDetails = &respr
		o.beginListCloudAccountDetails.add(req, beginListCloudAccountDetails)
	}

	resp, err := server.PollerResponderNext(beginListCloudAccountDetails, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted}, resp.StatusCode) {
		o.beginListCloudAccountDetails.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginListCloudAccountDetails) {
		o.beginListCloudAccountDetails.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginListSaasSubscriptionDetails(req *http.Request) (*http.Response, error) {
	if o.srv.BeginListSaasSubscriptionDetails == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginListSaasSubscriptionDetails not implemented")}
	}
	beginListSaasSubscriptionDetails := o.beginListSaasSubscriptionDetails.get(req)
	if beginListSaasSubscriptionDetails == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default/listSaasSubscriptionDetails`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		respr, errRespr := o.srv.BeginListSaasSubscriptionDetails(req.Context(), nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginListSaasSubscriptionDetails = &respr
		o.beginListSaasSubscriptionDetails.add(req, beginListSaasSubscriptionDetails)
	}

	resp, err := server.PollerResponderNext(beginListSaasSubscriptionDetails, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted}, resp.StatusCode) {
		o.beginListSaasSubscriptionDetails.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginListSaasSubscriptionDetails) {
		o.beginListSaasSubscriptionDetails.remove(req)
	}

	return resp, nil
}

func (o *OracleSubscriptionsServerTransport) dispatchBeginUpdate(req *http.Request) (*http.Response, error) {
	if o.srv.BeginUpdate == nil {
		return nil, &nonRetriableError{errors.New("fake for method BeginUpdate not implemented")}
	}
	beginUpdate := o.beginUpdate.get(req)
	if beginUpdate == nil {
		const regexStr = `/subscriptions/(?P<subscriptionId>[!#&$-;=?-\[\]_a-zA-Z0-9~%@]+)/providers/Oracle\.Database/oracleSubscriptions/default`
		regex := regexp.MustCompile(regexStr)
		matches := regex.FindStringSubmatch(req.URL.EscapedPath())
		if len(matches) < 2 {
			return nil, fmt.Errorf("failed to parse path %s", req.URL.Path)
		}
		body, err := server.UnmarshalRequestAsJSON[armoracledatabase.OracleSubscriptionUpdate](req)
		if err != nil {
			return nil, err
		}
		respr, errRespr := o.srv.BeginUpdate(req.Context(), body, nil)
		if respErr := server.GetError(errRespr, req); respErr != nil {
			return nil, respErr
		}
		beginUpdate = &respr
		o.beginUpdate.add(req, beginUpdate)
	}

	resp, err := server.PollerResponderNext(beginUpdate, req)
	if err != nil {
		return nil, err
	}

	if !contains([]int{http.StatusOK, http.StatusAccepted}, resp.StatusCode) {
		o.beginUpdate.remove(req)
		return nil, &nonRetriableError{fmt.Errorf("unexpected status code %d. acceptable values are http.StatusOK, http.StatusAccepted", resp.StatusCode)}
	}
	if !server.PollerResponderMore(beginUpdate) {
		o.beginUpdate.remove(req)
	}

	return resp, nil
}

// set this to conditionally intercept incoming requests to OracleSubscriptionsServerTransport
var oracleSubscriptionsServerTransportInterceptor interface {
	// Do returns true if the server transport should use the returned response/error
	Do(*http.Request) (*http.Response, error, bool)
}
