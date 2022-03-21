//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package tracing

import (
	"context"
)

// Provider contains the global tracing provider for Azure SDKs.
// It defaults to a no-op tracer.
var Provider TracerProvider

// TracerProvider abstracts the creation of new Tracers.
// The traceName indicates the name of the trace to which the spans belong.
type TracerProvider interface {
	Tracer(traceName string) Tracer
}

// Tracer abstracts the creation of spans.
type Tracer interface {
	Start(ctx context.Context, spanName string, options *SpanOptions) (context.Context, Span)
}

// Span is a single unit of a trace.
// A trace can contain multiple spans.
type Span interface {
	// End terminates the span and MUST be called before the span leaves scope.
	// Any further updates to the span will be ignored after End is called.
	End(code StatusCode, errorDesc string)

	// Recording returns true if the span is active and can record events.
	Recording() bool

	// RecordEvent adds the named event with any specified KeyValuePairs.
	RecordEvent(name string, attrs ...KeyValuePair)

	// RecordError will add err as an exception span event for this span.
	RecordError(err error)
}

// SpanOptions contains optional settings for creating a span.
type SpanOptions struct {
	// IncludeTimestamp enable time stamps for the span.
	IncludeTimestamp bool

	// Attributes contains key-value pairs of attributes for the span.
	Attributes []KeyValuePair
}

// StatusCode indicates the state of the trace.
type StatusCode uint32

const (
	// StatusCodeNone is the default status code.
	StatusCodeNone = 0

	// StatusCodeError indicates the operation contains an error.
	StatusCodeError = 1

	// StatusCodeOK indicates the operation completed successfully.
	StatusCodeOK = 2
)

// KeyValuePair is a key-value pair of strings.
type KeyValuePair struct {
	Key string
	Val string
}

///////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	Provider = noopTraceProvider{}
}

type noopTraceProvider struct{}

func (noopTraceProvider) Tracer(string) Tracer {
	return noopTracer{}
}

type noopTracer struct{}

func (noopTracer) Start(ctx context.Context, spanName string, opts *SpanOptions) (context.Context, Span) {
	return ctx, noopSpan{}
}

type noopSpan struct{}

func (noopSpan) End(StatusCode, string) {}

func (noopSpan) RecordEvent(string, ...KeyValuePair) {}

func (noopSpan) Recording() bool { return false }

func (noopSpan) RecordError(error) {}
