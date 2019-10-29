// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azfile

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

type DirectoryClient struct {
	u *url.URL
	p azcore.Pipeline
}

func NewDirectoryClient(endpoint string, cred azcore.Credential, options azcore.PipelineOptions) (DirectoryClient, error) {
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
	return NewDirectoryClientWithPipeline(endpoint, p)
}

func NewDirectoryClientWithPipeline(endpoint string, p azcore.Pipeline) (DirectoryClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return DirectoryClient{}, err
	}
	return DirectoryClient{u: u, p: p}, nil
}

func (c DirectoryClient) ServiceVersion() string {
	// this is a method instead of a package-level const to handle the case of composite services
	return "2017-07-29"
}

// ListFilesAndDirectoriesSegment returns a list of files or directories under the specified share or directory. It
// lists the contents only for a single level of the directory hierarchy.
//
// prefix is filters the results to return only entries whose name begins with the specified prefix. sharesnapshot is
// the snapshot parameter is an opaque DateTime value that, when present, specifies the share snapshot to query. marker
// is a string value that identifies the portion of the list to be returned with the next list operation. The operation
// returns a marker value within the response body if the list returned was not complete. The marker value may then be
// used in a subsequent call to request the next set of list items. The marker value is opaque to the client.
// maxresults is specifies the maximum number of entries to return. If the request does not specify maxresults, or
// specifies a value greater than 5,000, the server will return up to 5,000 items. timeout is the timeout parameter is
// expressed in seconds. For more information, see <a
// href="https://docs.microsoft.com/en-us/rest/api/storageservices/Setting-Timeouts-for-File-Service-Operations?redirectedfrom=MSDN">Setting
// Timeouts for File Service Operations.</a>
func (c DirectoryClient) ListFilesAndDirectories(options *ListFilesAndDirectoriesOptions) *ListFilesAndDirectoriesIterator {
	if options == nil {
		options = &ListFilesAndDirectoriesOptions{}
	}
	return &ListFilesAndDirectoriesIterator{
		client: c,
		op:     options,
	}
}

func (c DirectoryClient) listFilesAndDirectoriesPreparer(options *ListFilesAndDirectoriesOptions) *azcore.Request {
	req := c.p.NewRequest(http.MethodGet, *c.u)
	if options != nil {
		if options.Prefix != nil && len(*options.Prefix) > 0 {
			req.SetQueryParam("prefix", *options.Prefix)
		}
		if options.Sharesnapshot != nil && len(*options.Sharesnapshot) > 0 {
			req.SetQueryParam("sharesnapshot", *options.Sharesnapshot)
		}
		if options.Marker != nil && len(*options.Marker) > 0 {
			req.SetQueryParam("marker", *options.Marker)
		}
		if options.Maxresults != nil {
			req.SetQueryParam("maxresults", strconv.FormatInt(int64(*options.Maxresults), 10))
		}
		if options.Timeout != nil {
			req.SetQueryParam("timeout", strconv.FormatInt(int64(*options.Timeout), 10))
		}
	}
	req.SetQueryParam("restype", "directory")
	req.SetQueryParam("comp", "list")
	req.Header.Set("x-ms-version", c.ServiceVersion())
	return req
}

// listFilesAndDirectoriesSegmentResponder handles the response to the ListFilesAndDirectoriesSegment request.
func (c DirectoryClient) listFilesAndDirectoriesResponder(resp *azcore.Response) (*ListFilesAndDirectoriesPage, error) {
	if err := resp.CheckStatusCode(http.StatusOK); err != nil {
		return nil, err
	}
	result := &ListFilesAndDirectoriesPage{response: resp}
	return result, resp.UnmarshalAsXML(result)
}
