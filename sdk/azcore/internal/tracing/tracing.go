//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package tracing

import (
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
)

var tracerSync sync.Once

// Tracer provides tracing facilities for azcore.
var Tracer tracing.Tracer

func Init() {
	tracerSync.Do(func() {
		Tracer = tracing.Provider.Tracer("github.com/Azure/azure-sdk-for-go/sdk/azcore@" + shared.Version)
	})
}

const (
	// StatusCodeNone is the default status code.
	StatusCodeNone tracing.StatusCode = tracing.StatusCodeNone

	// StatusCodeError indicates the operation contains an error.
	StatusCodeError tracing.StatusCode = tracing.StatusCodeError

	// StatusCodeOK indicates the operation completed successfully.
	StatusCodeOK tracing.StatusCode = tracing.StatusCodeOK
)

type KeyValuePair = tracing.KeyValuePair

func WithKeyValuePair(key, val string) KeyValuePair {
	return KeyValuePair{Key: key, Val: val}
}
