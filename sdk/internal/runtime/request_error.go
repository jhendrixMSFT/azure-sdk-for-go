// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import "net/http"

// NewRequestError wraps the specified error with an error that provides access to an HTTP response.
func NewRequestError(inner error, resp *http.Response) error {
	return &RequestError{inner: inner, resp: resp}
}

// RequestError associates an error with an HTTP response.
type RequestError struct {
	inner error
	resp  *http.Response
}

// Error implements the error interface for type Error.
func (e *RequestError) Error() string {
	return e.inner.Error()
}

// Unwrap returns the inner error.
func (e *RequestError) Unwrap() error {
	return e.inner
}

// Response returns the HTTP response associated with this error.
func (e *RequestError) Response() *http.Response {
	return e.resp
}
