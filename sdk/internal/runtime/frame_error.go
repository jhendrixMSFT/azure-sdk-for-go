// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"fmt"
	"runtime"
)

// NewFrameError wraps the specified error with an error that provides stack frame information.
// Call this at the inner error's origin to provide file name and line number info with the error.
// DO NOT ARBITRARILY CALL THIS TO WRAP ERRORS!  There MUST be only ONE error of this type in the chain.
func NewFrameError(inner error, stackTrace bool, skipFrames, totalFrames int) error {
	fe := frameError{inner: inner, info: "stack trace unavailable"}
	if stackTrace {
		// the skipFrames+2 is to skip StackTrace and ourselves
		fe.info = StackTrace(skipFrames+2, totalFrames)
	} else if pc, file, line, ok := runtime.Caller(skipFrames + 1); ok {
		// the skipFrames + 1 is to skip ourselves
		frame := runtime.FuncForPC(pc)
		fe.info = fmt.Sprintf("%s()\n\t%s:%d\n", frame.Name(), file, line)
	}
	return &fe
}

// contains stack frame info
type frameError struct {
	inner error
	info  string
}

// Error implements the error interface for type frameError.
func (f *frameError) Error() string {
	return fmt.Sprintf("%s: \n%s\n", f.inner.Error(), f.info)
}

// Unwrap returns the inner error.
func (f *frameError) Unwrap() error {
	return f.inner
}
