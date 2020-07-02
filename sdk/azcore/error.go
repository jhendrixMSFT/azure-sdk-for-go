// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azcore

import (
	"errors"
	"net/http"

	azruntime "github.com/Azure/azure-sdk-for-go/sdk/internal/runtime"
)

var (
	// ErrNoMorePolicies is returned from Request.Next() if there are no more policies in the pipeline.
	ErrNoMorePolicies = errors.New("no more policies")
)

var (
	// StackFrameCount contains the number of stack frames to include when a trace is being collected.
	StackFrameCount = 32
)

// NewRequestError returns a new instance of the RequestError type.
func NewRequestError(resp *http.Response) error {
	return azruntime.NewStackError(&RequestError{Response: resp}, Log().Should(LogStackTrace), 1, StackFrameCount)
}

type RequestError struct {
	Response *http.Response
}

// Error implements the error interface for type Error.
func (e *RequestError) Error() string {
	return e.Response.Status
}
