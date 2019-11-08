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

type FileClient struct {
	u *url.URL
	p azcore.Pipeline
}

func NewFileClient(endpoint string, cred azcore.Credential, options azcore.PipelineOptions) (FileClient, error) {
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
	return NewFileClientWithPipeline(endpoint, p)
}

func NewFileClientWithPipeline(endpoint string, p azcore.Pipeline) (FileClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return FileClient{}, err
	}
	return FileClient{u: u, p: p}, nil
}

func (c FileClient) ServiceVersion() string {
	// this is a method instead of a package-level const to handle the case of composite services
	return "2017-07-29"
}

// Create creates a new file or replaces a file. Note it only initializes the file with no content.
//
// fileContentLength is specifies the maximum size for the file, up to 1 TB. timeout is the timeout parameter is
// expressed in seconds. For more information, see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a> fileContentType is sets the MIME content type of the file. The default
// type is 'application/octet-stream'. fileContentEncoding is specifies which content encodings have been applied to
// the file. fileContentLanguage is specifies the natural languages used by this resource. fileCacheControl is sets the
// file's cache control. The File service stores this value but does not use or modify it. fileContentMD5 is sets the
// file's MD5 hash. fileContentDisposition is sets the file's Content-Disposition header. metadata is a name-value pair
// to associate with a file storage object.
func (c FileClient) Create(ctx context.Context, fileContentLength int64, options *FileCreateOptions) (*FileCreateResponse, error) {
	msg := c.createPreparer(fileContentLength, options)
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.createResponder(resp)
}

// createPreparer prepares the Create request.
func (c FileClient) createPreparer(fileContentLength int64, options *FileCreateOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodPut, *c.u)
	if options != nil {
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
		if options.FileContentType != nil {
			req.Header.Set("x-ms-content-type", *options.FileContentType)
		}
		if options.FileContentEncoding != nil {
			req.Header.Set("x-ms-content-encoding", *options.FileContentEncoding)
		}
		if options.FileContentLanguage != nil {
			req.Header.Set("x-ms-content-language", *options.FileContentLanguage)
		}
		if options.FileCacheControl != nil {
			req.Header.Set("x-ms-cache-control", *options.FileCacheControl)
		}
		if options.FileContentMD5 != nil {
			req.Header.Set("x-ms-content-md5", *options.FileContentMD5)
		}
		if options.FileContentDisposition != nil {
			req.Header.Set("x-ms-content-disposition", *options.FileContentDisposition)
		}
		if options.Metadata != nil {
			for k, v := range options.Metadata {
				req.Header.Set("x-ms-meta-"+k, v)
			}
		}
	}
	req.Header.Set("x-ms-version", c.ServiceVersion())
	req.Header.Set("x-ms-content-length", strconv.FormatInt(fileContentLength, 10))
	req.Header.Set("x-ms-type", "file")
	return req
}

// createResponder handles the response to the Create request.
func (c FileClient) createResponder(resp *azcore.Response) (*FileCreateResponse, error) {
	if err := resp.CheckStatusCode(http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	return &FileCreateResponse{response: resp}, nil
}

func (c FileClient) GetProperties(ctx context.Context, options *FileGetPropertiesOptions) (*FileGetPropertiesResponse, error) {
	msg := c.getPropertiesPreparer(options)
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.getPropertiesResponder(resp)
}

func (c FileClient) getPropertiesPreparer(options *FileGetPropertiesOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodHead, *c.u)
	if options != nil {
		if options.ShareSnapshot != nil && len(*options.ShareSnapshot) > 0 {
			req.SetQueryParam("sharesnapshot", *options.ShareSnapshot)
		}
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
	}
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req
}

// getPropertiesResponder handles the response to the GetProperties request.
func (c FileClient) getPropertiesResponder(resp *azcore.Response) (*FileGetPropertiesResponse, error) {
	if err := resp.CheckStatusCode(http.StatusOK); err != nil {
		return nil, err
	}
	return &FileGetPropertiesResponse{response: resp}, nil
}

// GetRangeList returns the list of valid ranges for a file.
//
// sharesnapshot is the snapshot parameter is an opaque DateTime value that, when present, specifies the share snapshot
// to query. timeout is the timeout parameter is expressed in seconds. For more information, see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a> rangeParameter is specifies the range of bytes over which to list ranges,
// inclusively.
func (c FileClient) GetRangeList(ctx context.Context, options *FileGetRangeListOptions) (*Ranges, error) {
	msg := c.getRangeListPreparer(options)
	resp, err := msg.Do(ctx)
	if err != nil {
		return nil, err
	}
	return c.getRangeListResponder(resp)
}

// getRangeListPreparer prepares the GetRangeList request.
func (c FileClient) getRangeListPreparer(options *FileGetRangeListOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodGet, *c.u)
	if options != nil {
		if options.Sharesnapshot != nil && len(*options.Sharesnapshot) > 0 {
			req.SetQueryParam("sharesnapshot", *options.Sharesnapshot)
		}
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
		if options.RangeParameter != nil {
			req.Header.Set("x-ms-range", *options.RangeParameter)
		}
	}
	req.SetQueryParam("comp", "rangelist")
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req
}

// getRangeListResponder handles the response to the GetRangeList request.
func (c FileClient) getRangeListResponder(resp *azcore.Response) (*Ranges, error) {
	if err := resp.CheckStatusCode(http.StatusOK); err != nil {
		return nil, err
	}
	result := &Ranges{response: resp}
	return result, resp.UnmarshalAsXML(result)
}
