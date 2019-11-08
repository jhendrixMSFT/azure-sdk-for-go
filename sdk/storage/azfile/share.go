// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azfile

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

type ShareClient struct {
	u *url.URL
	p azcore.Pipeline
}

func NewShareClient(endpoint string, cred azcore.Credential, options azcore.PipelineOptions) (ShareClient, error) {
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
	return NewShareClientWithPipeline(endpoint, p)
}
func NewShareClientWithPipeline(endpoint string, p azcore.Pipeline) (ShareClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ShareClient{}, err
	}
	return ShareClient{u: u, p: p}, nil
}

func (c ShareClient) ServiceVersion() string {
	return "2017-07-29"
}

// Create creates a new share under the specified account. If the share with the same name already exists, the
// operation fails.
//
// timeout is the timeout parameter is expressed in seconds. For more information, see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a> metadata is a name-value pair to associate with a file storage object.
// quota is specifies the maximum size of the share, in gigabytes.
func (c ShareClient) Create(ctx context.Context, options *ShareCreateOptions) (*ShareCreateResponse, error) {
	msg := c.createPreparer(options)
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.createResponder(resp)
}

// createPreparer prepares the Create request.
func (c ShareClient) createPreparer(options *ShareCreateOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodPut, *c.u)
	if options != nil {
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
		if options.Metadata != nil {
			for k, v := range options.Metadata {
				req.Header.Set("x-ms-meta-"+k, v)
			}
		}
		if options.Quota != nil {
			req.Header.Set("x-ms-share-quota", strconv.FormatInt(int64(*options.Quota), 10))
		}
	}
	req.SetQueryParam("restype", "share")
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req
}

// createResponder handles the response to the Create request.
func (c ShareClient) createResponder(resp *azcore.Response) (*ShareCreateResponse, error) {
	if err := resp.CheckStatusCode(http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	return &ShareCreateResponse{response: resp}, nil
}

// GetAccessPolicy returns information about stored access policies specified on the share.
//
// timeout is the timeout parameter is expressed in seconds. For more information, see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a>
func (c ShareClient) GetAccessPolicy(ctx context.Context, options *ShareGetAccessPolicyOptions) (*SignedIdentifiers, error) {
	msg := c.getAccessPolicyPreparer(options)
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.getAccessPolicyResponder(resp)
}

// getAccessPolicyPreparer prepares the GetAccessPolicy request.
func (c ShareClient) getAccessPolicyPreparer(options *ShareGetAccessPolicyOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodGet, *c.u)
	if options != nil {
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
	}
	req.SetQueryParam("restype", "share")
	req.SetQueryParam("comp", "acl")
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req
}

// getAccessPolicyResponder handles the response to the GetAccessPolicy request.
func (c ShareClient) getAccessPolicyResponder(resp *azcore.Response) (*SignedIdentifiers, error) {
	if err := resp.CheckStatusCode(http.StatusOK); err != nil {
		return nil, err
	}
	result := &SignedIdentifiers{response: resp}
	return result, resp.UnmarshalAsXML(result)
}

// SetAccessPolicy sets a stored access policy for use with shared access signatures.
//
// shareACL is the ACL for the share. timeout is the timeout parameter is expressed in seconds. For more information,
// see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a>
func (c ShareClient) SetAccessPolicy(ctx context.Context, shareACL []SignedIdentifier, options *ShareSetAccessPolicyOptions) (*ShareSetAccessPolicyResponse, error) {
	msg, err := c.setAccessPolicyPreparer(shareACL, options)
	if err != nil {
		return nil, err
	}
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.setAccessPolicyResponder(resp)
}

// setAccessPolicyPreparer prepares the SetAccessPolicy request.
func (c ShareClient) setAccessPolicyPreparer(shareACL []SignedIdentifier, options *ShareSetAccessPolicyOptions) (*azcore.Request, error) {
	req := c.p.NewRequest(http.MethodPut, *c.u)
	if options != nil {
		req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
	}
	req.SetQueryParam("restype", "share")
	req.SetQueryParam("comp", "acl")
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req, req.MarshalAsXML(SignedIdentifiers{Value: shareACL})
}

// setAccessPolicyResponder handles the response to the SetAccessPolicy request.
func (c ShareClient) setAccessPolicyResponder(resp *azcore.Response) (*ShareSetAccessPolicyResponse, error) {
	if err := resp.CheckStatusCode(http.StatusOK); err != nil {
		return nil, err
	}
	return &ShareSetAccessPolicyResponse{response: resp}, nil
}
