// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azcore

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
)

var (
	// ErrNoMorePolicies is returned from Request.Next() if there are no more policies in the pipeline.
	ErrNoMorePolicies = errors.New("no more policies")
)

// contains stack frame info
type frameInfo struct {
	where string
	stack string
}

func (f frameInfo) Where() string {
	if f.where == "" {
		return "location unavailable"
	}
	return f.where
}

func (f frameInfo) Stack() string {
	if f.stack == "" {
		return "stack trace unavailable"
	}
	return f.stack
}

func (f frameInfo) zero() bool {
	return f.where == "" && f.stack == ""
}

// Error is the outermost error type returned from an API call.
// Its purpose is to wrap an existing error, providing a stack
// trace where the error happened and an *http.Response if available.
type Error struct {
	inner error
	resp  *http.Response
	fi    frameInfo
}

// NewError returns a new instance of the Error type.
func NewError(inner error, resp *http.Response) error {
	fi := frameInfo{}
	if pc, file, line, ok := runtime.Caller(1); ok {
		frames := runtime.CallersFrames([]uintptr{pc})
		frame, _ := frames.Next()
		fi.where = fmt.Sprintf("%s()\n\t%s:%d\n", frame.Function, file, line)
	}
	if Log().Should(LogStackTrace) {
		fi.stack = string(stack())
	}
	return &Error{inner: inner, resp: resp, fi: fi}
}

// Error implements the error interface for type Error.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: \n%s\n", e.inner.Error(), e.Where())
}

// Response returns the underlying HTTP response.
// Can return nil if no HTTP response was available when the error happened.
func (e *Error) Response() *http.Response {
	return e.resp
}

// Stack returns the stack trace where the error was created.
func (e *Error) Stack() string {
	return e.fi.Stack()
}

// String implements the stringer interface for type Error.
// It concatenates the output from Error() and Stack().
func (e *Error) String() string {
	return fmt.Sprintf("%s: \n%s\n", e.inner.Error(), e.Stack())
}

// Unwrap returns the inner error.
func (e *Error) Unwrap() error {
	return e.inner
}

// Where returns the the file and line number where the error was created.
func (e *Error) Where() string {
	return e.fi.Where()
}
