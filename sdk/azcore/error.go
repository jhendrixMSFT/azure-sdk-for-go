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

// Responder provides access to an HTTP response if available.
// Errors returned from failed API calls will implement this interface.
type Responder interface {
	Response() *http.Response
}

var _ Responder = (*azruntime.RequestError)(nil)
