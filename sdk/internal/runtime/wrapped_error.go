// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import "errors"

// NewWrappedError wraps the inner error with the outer error.
// The returned error type behaves as the outer error.
func NewWrappedError(outer, inner error) error {
	return &wrappedError{outer: outer, inner: inner}
}

type wrappedError struct {
	outer error
	inner error
}

func (w *wrappedError) As(target interface{}) bool {
	return errors.As(w.outer, target)
}

func (w *wrappedError) Is(target error) bool {
	return errors.Is(w.outer, target)
}

func (w *wrappedError) Error() string {
	return w.outer.Error()
}

func (w *wrappedError) Unwrap() error {
	return w.inner
}
