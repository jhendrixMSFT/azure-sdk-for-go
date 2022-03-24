//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package tracing

import (
	"context"
)

// ProviderImpl contains the underlying implementation for Provider.
// Any zero-values will have their default, no-op behavior.
type ProviderImpl struct {
	Tracer ProviderTracer
}

// NewProvider returns a Provider with the specified implementation.
func NewProvider(impl ProviderImpl) Provider {
	return Provider{
		impl: impl,
	}
}

// Provider provides access to Tracer instances.
// It defaults to a no-op provider.
type Provider struct {
	impl ProviderImpl
}

// Tracer returns a Tracer for the specified namespace and version.
func (p Provider) Tracer(namespace, version string) (tracer Tracer) {
	if p.impl.Tracer != nil {
		tracer = p.impl.Tracer.Tracer(namespace, version)
	}
	return
}

// ProviderTracer abstracts the Tracer method for a Provider.
type ProviderTracer interface {
	Tracer(namespace, version string) Tracer
}

var _ ProviderTracer = (*Provider)(nil)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

// TracerImpl contains the underlying implementation for Tracer.
// Any zero-values will have their default, no-op behavior.
type TracerImpl struct {
	Start TracerStarter
}

// NewTracer returns a Tracer with the specified implementation.
func NewTracer(impl TracerImpl) Tracer {
	return Tracer{
		impl: impl,
	}
}

// Tracer provides the creation of instances of a Span.
type Tracer struct {
	impl TracerImpl
}

// Start implements the TracerStarter interface for the TracerStartFunc type.
func (t Tracer) Start(ctx context.Context, spanName string, options *SpanOptions) (context.Context, Span) {
	if t.impl.Start != nil {
		return t.impl.Start.Start(ctx, spanName, options)
	}
	return ctx, Span{}
}

// TracerStarter abstracts the Start method for a Tracer.
type TracerStarter interface {
	Start(ctx context.Context, spanName string, options *SpanOptions) (context.Context, Span)
}

var _ TracerStarter = (*Tracer)(nil)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

// SpanImpl contains the underlying implementation for Span.
// Any zero-values will have their default, no-op behavior.
type SpanImpl struct {
	// Ender is the implementation for the End method.
	Ender SpanEnder
}

// NewSpan returns a Span with the specified implementation.
func NewSpan(impl SpanImpl) Span {
	return Span{
		impl: impl,
	}
}

// Span is a single unit of a trace.  A trace can contain multiple spans.
// A zero-value Span provides a no-op implementation.
type Span struct {
	impl SpanImpl
}

// End terminates the span and MUST be called before the span leaves scope.
// Any further updates to the span will be ignored after End is called.
func (s Span) End(code StatusCode, err error, errDesc string) {
	if s.impl.Ender != nil {
		s.impl.Ender.End(code, err, errDesc)
	}
}

var _ SpanEnder = (*Span)(nil)

// SpanEnder abstracts the End method for a Span.
type SpanEnder interface {
	End(code StatusCode, err error, errDesc string)
}

// SpanOptions contains optional settings for creating a span.
type SpanOptions struct {
	// Attributes contains key-value pairs of attributes for the span.
	Attributes []KeyValuePair
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

// KeyValueConstraint contains the type constraints for the value in KeyValuePair.
type KeyValueConstraint interface {
	~int64 | ~float64 | ~int | ~bool | ~string
}

// NewKeyValuePair returns a new KeyValuePair with the specified values.
func NewKeyValuePair[T KeyValueConstraint](key string, val T) KeyValuePair {
	return KeyValuePair{
		k: key,
		v: val,
	}
}

// KeyValuePair is a key-value pair.
type KeyValuePair struct {
	k string
	v interface{}
}

// Key returns the key for this KeyValuePair.
func (k KeyValuePair) Key() string {
	return k.k
}

// Value returns the value for this KeyValuePair.
// Its type is constrained to one of the types in KeyValueConstraint.
func (k KeyValuePair) Value() interface{} {
	return k.v
}

// StatusCode indicates the state of the trace.
type StatusCode uint32

const (
	// StatusCodeNone is the default status code.
	StatusCodeNone StatusCode = 0

	// StatusCodeError indicates the operation contains an error.
	StatusCodeError StatusCode = 1

	// StatusCodeOK indicates the operation completed successfully.
	StatusCodeOK StatusCode = 2
)
