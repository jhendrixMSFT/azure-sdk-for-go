// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azfile

import (
	"context"
	"encoding/xml"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// AccessPolicy - An Access policy.
type AccessPolicy struct {
	// Start - The date-time the policy is active.
	Start *time.Time `xml:"Start"`
	// Expiry - The date-time the policy expires.
	Expiry *time.Time `xml:"Expiry"`
	// Permission - The permissions for the ACL policy.
	Permission *string `xml:"Permission"`
}

// DirectoryEntry - Directory entry.
type DirectoryEntry struct {
	// XMLName is used for marshalling and is subject to removal in a future release.
	XMLName xml.Name `xml:"Directory"`
	// Name - Name of the entry.
	Name string `xml:"Name"`
}

type ListFilesAndDirectoriesOptions struct {
	Prefix        *string
	Sharesnapshot *string
	Marker        *string
	Maxresults    *int32
	Timeout       *int32
}

type FileCreateOptions struct {
	Timeout                *int32
	FileContentType        *string
	FileContentEncoding    *string
	FileContentLanguage    *string
	FileCacheControl       *string
	FileContentMD5         *string
	FileContentDisposition *string
	Metadata               map[string]string
}

// FileCreateResponse ...
type FileCreateResponse struct {
	response *azcore.Response
}

// Response returns the raw HTTP response object.
func (fcr FileCreateResponse) Response() *azcore.Response {
	return fcr.response
}

// FileEntry - File entry.
type FileEntry struct {
	// XMLName is used for marshalling and is subject to removal in a future release.
	XMLName xml.Name `xml:"File"`
	// Name - Name of the entry.
	Name       string        `xml:"Name"`
	Properties *FileProperty `xml:"Properties"`
}

type FileGetPropertiesOptions struct {
	ShareSnapshot *string
	Timeout       *int32
}

type FileGetPropertiesResponse struct {
	response *azcore.Response
}

func (f FileGetPropertiesResponse) Response() *azcore.Response {
	return f.response
}

type FileGetRangeListOptions struct {
	Sharesnapshot  *string
	Timeout        *int32
	RangeParameter *string
}

// FileProperty - File properties.
type FileProperty struct {
	// ContentLength - Content length of the file. This value may not be up-to-date since an SMB client may have modified the file locally. The value of Content-Length may not reflect that fact until the handle is closed or the op-lock is broken. To retrieve current property values, call Get File Properties.
	ContentLength int64 `xml:"Content-Length"`
}

type ListFilesAndDirectoriesIterator struct {
	client DirectoryClient
	op     *ListFilesAndDirectoriesOptions
	page   *ListFilesAndDirectoriesPage
	Err    error
}

// Page returns the current ListFilesAndDirectoriesPage.
func (iter ListFilesAndDirectoriesIterator) Page() *ListFilesAndDirectoriesPage {
	return iter.page
}

// NextPage returns true if the iterator advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (iter *ListFilesAndDirectoriesIterator) NextPage(ctx context.Context) bool {
	if iter.page.done() {
		return false
	}
	msg := iter.client.listFilesAndDirectoriesPreparer(iter.op)
	resp, err := msg.Do(ctx)
	if err != nil {
		iter.Err = err
		return false
	}
	next, err := iter.client.listFilesAndDirectoriesResponder(resp)
	if err != nil {
		iter.Err = err
		return false
	}
	iter.page = next
	iter.op.Marker = iter.page.NextMarker
	return true
}

// FilesAndDirectoriesPage - An enumeration of directories and files.
type ListFilesAndDirectoriesPage struct {
	response *azcore.Response
	// XMLName is used for marshalling and is subject to removal in a future release.
	XMLName         xml.Name         `xml:"EnumerationResults"`
	ServiceEndpoint string           `xml:"ServiceEndpoint,attr"`
	ShareName       string           `xml:"ShareName,attr"`
	ShareSnapshot   *string          `xml:"ShareSnapshot,attr"`
	DirectoryPath   string           `xml:"DirectoryPath,attr"`
	Prefix          string           `xml:"Prefix"`
	Marker          *string          `xml:"Marker"`
	MaxResults      *int32           `xml:"MaxResults"`
	Files           []FileEntry      `xml:"Entries>File"`
	Directories     []DirectoryEntry `xml:"Entries>Directory"`
	NextMarker      *string          `xml:"NextMarker"`
}

func (l ListFilesAndDirectoriesPage) Response() *azcore.Response {
	return l.response
}

func (l *ListFilesAndDirectoriesPage) done() bool {
	return l != nil && len(*l.NextMarker) == 0
}

// Range - An Azure Storage file range.
type Range struct {
	// Start - Start of the range.
	Start int64 `xml:"Start"`
	// End - End of the range.
	End int64 `xml:"End"`
}

// Ranges - Wraps the response from the fileClient.GetRangeList method.
type Ranges struct {
	response *azcore.Response
	Items    []Range `xml:"Range"`
}

func (r Ranges) Response() *azcore.Response {
	return r.response
}

type ShareCreateOptions struct {
	Timeout  *int32
	Metadata map[string]string
	Quota    *int32
}

// ShareCreateResponse ...
type ShareCreateResponse struct {
	response *azcore.Response
}

// Response returns the raw HTTP response object.
func (scr ShareCreateResponse) Response() *azcore.Response {
	return scr.response
}

type ShareGetAccessPolicyOptions struct {
	Timeout *int32
}

type ShareSetAccessPolicyOptions struct {
	Timeout *int32
}

// ShareSetAccessPolicyResponse ...
type ShareSetAccessPolicyResponse struct {
	response *azcore.Response
}

// Response returns the raw HTTP response object.
func (ssapr ShareSetAccessPolicyResponse) Response() *azcore.Response {
	return ssapr.response
}

// SignedIdentifier - Signed identifier.
type SignedIdentifier struct {
	// ID - A unique id.
	ID string `xml:"Id"`
	// AccessPolicy - The access policy.
	AccessPolicy *AccessPolicy `xml:"AccessPolicy"`
}

// SignedIdentifiers ...
type SignedIdentifiers struct {
	response *azcore.Response
	Value    []SignedIdentifier `xml:"SignedIdentifier"`
}
