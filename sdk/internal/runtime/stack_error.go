// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"fmt"
	"runtime"
)

// NewStackError wraps the specified error with an error that provides stack frame information.
func NewStackError(inner error, stackTrace bool, skipFrames, totalFrames int) error {
	se := stackError{inner: inner}
	// the skipFrames + 1 is to skip ourselves
	if pc, file, line, ok := runtime.Caller(skipFrames + 1); ok {
		frame := runtime.FuncForPC(pc)
		se.where = fmt.Sprintf("%s()\n\t%s:%d\n", frame.Name(), file, line)
	}
	if stackTrace {
		// the skipFrames+2 is to skip StackTrace and ourselves
		se.stack = StackTrace(skipFrames+2, totalFrames)
	}
	return &se
}

// contains stack frame info
type stackError struct {
	inner error
	where string
	stack string
}

// Error implements the error interface for type stackError.
func (s *stackError) Error() string {
	return fmt.Sprintf("%s: \n%s\n", s.inner.Error(), s.Where())
}

// StackTrace returns the stack trace where the error was created.
func (s *stackError) StackTrace() string {
	if s.stack == "" {
		return "stack trace unavailable"
	}
	return s.stack
}

// Unwrap returns the inner error.
func (s *stackError) Unwrap() error {
	return s.inner
}

// Where returns the the file and line number where the error was created.
func (s *stackError) Where() string {
	if s.where == "" {
		return "location unavailable"
	}
	return s.where
}
