//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
)

// NewRetryPolicy creates a policy object configured using the specified options.
// Pass nil to accept the default values; this is the same as passing a zero-value options.
func NewTracingPolicy(p tracing.Provider) policy.Policy {
	return &tracingPolicy{
		tracer: p.Tracer("github.com/Azure/azure-sdk-for-go/sdk/azcore", shared.Version),
	}
}

type tracingPolicy struct {
	tracer tracing.Tracer
}

func (t *tracingPolicy) Do(req *policy.Request) (*http.Response, error) {
	// TODO: clean up name, include try number
	ctx, span := t.tracer.Start(req.Raw().Context(), "azcore.tracingPolicy.Do", &tracing.SpanOptions{
		Kind: tracing.SpanKindClient,
		Attributes: []tracing.KeyValuePair{
			tracing.NewKeyValuePair("http.method", http.MethodDelete),
			tracing.NewKeyValuePair("http.url", req.Raw().URL.String()),
			tracing.NewKeyValuePair("http.user_agent", req.Raw().UserAgent()),
		},
	})
	req = req.WithContext(ctx)

	status := tracing.StatusCodeNone
	var err error
	errDesc := ""
	defer func() {
		span.End(status, err, errDesc)
	}()

	if reqID := req.Raw().Header.Get("x-ms-client-request-id"); reqID != "" {
		span.SetAttributes(tracing.NewKeyValuePair("requestId", reqID))
	}

	var resp *http.Response
	resp, err = req.Next()
	if err != nil {
		status = tracing.StatusCodeError
		errDesc = "the operation failed"
	}
	if resp != nil {
		span.SetAttributes(tracing.NewKeyValuePair("http.status_code", resp.StatusCode))

		if reqID := resp.Header.Get("x-ms-request-id"); reqID != "" {
			span.SetAttributes(tracing.NewKeyValuePair("serviceRequestId", reqID))
		}
	}
	return resp, err
}
